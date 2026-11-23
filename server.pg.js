require("dotenv").config();

const express=require("express");
const session=require("express-session");
const PgSession=require("connect-pg-simple")(session);
const bcrypt=require("bcryptjs");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const multer=require("multer");
const path=require("path");
const fs=require("fs");
const crypto=require("crypto");
const {Pool}=require("pg");

if(!process.env.DATABASE_URL||!process.env.SESSION_SECRET){
  throw new Error("DATABASE_URL or SESSION_SECRET missing in .env");
}

const app=express();
const pool=new Pool({
  connectionString:process.env.DATABASE_URL,
  max:10,
  connectionTimeoutMillis:10000,
  idleTimeoutMillis:30000
});
const uploadDir=path.join(__dirname,"uploads");
fs.mkdirSync(uploadDir,{recursive:true});

pool.on("error",e=>console.error("PostgreSQL pool error:",e.message));

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(session({
  store:new PgSession({pool,createTableIfMissing:true}),
  secret:process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure:process.env.NODE_ENV==="production",
    path:"/",
      maxAge:28800000
  }
}));

app.get("/api/csrf-token",(q,s)=>{
  if(!q.session.csrfToken){
    q.session.csrfToken=crypto.randomBytes(32).toString("hex");
  }
  s.json({csrfToken:q.session.csrfToken});
});

app.use("/api",(q,s,n)=>{
  if(["GET","HEAD","OPTIONS"].includes(q.method))return n();

  const expected=String(q.session?.csrfToken||"");
  const supplied=String(q.get("x-csrf-token")||"");

  if(!expected||!supplied||
     expected.length!==supplied.length||
     !crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(supplied))){
    return s.status(403).json({error:"Security token မမှန်ပါ။ Page ကို Refresh လုပ်ပြီး ပြန်ကြိုးစားပါ။"});
  }
  n();
});

// Public uploads access disabled
app.use(express.static(path.join(__dirname,"public")));

const limiter=rateLimit({windowMs:900000,limit:8,standardHeaders:true,legacyHeaders:false,message:{error:"Login ကြိုးစားမှုများလွန်းပါတယ်။ ၁၅ မိနစ်စောင့်ပါ။"}});
const customerLimiter=rateLimit({windowMs:900000,limit:10});

const upload=multer({
  storage:multer.diskStorage({
    destination:(q,f,cb)=>cb(null,uploadDir),
    filename:(q,f,cb)=>cb(null,crypto.randomBytes(24).toString("hex"))
  }),
  limits:{fileSize:5242880},
  fileFilter:(q,f,cb)=>cb(
    null,
    ["image/jpeg","image/png","image/webp"].includes(f.mimetype)
  )
});

function admin(q,s,n){
  if(q.session.admin)return n();
  s.status(401).json({error:"Admin login required"});
}

function customer(q,s,n){
  if(q.session.customerId)return n();
  s.status(401).json({error:"Customer login လုပ်ပါ။"});
}

function startCustomerSession(q,s,id){
  q.session.regenerate(err=>{
    if(err)return s.status(500).json({error:"Session error"});
    q.session.customerId=id;
    q.session.csrfToken=crypto.randomBytes(32).toString("hex");
    q.session.save(e=>{
      if(e)return s.status(500).json({error:"Session save error"});
      s.json({ok:true,csrfToken:q.session.csrfToken});
    });
  });
}

function activeValue(v){
  if(v===true||v===1||v==="1")return 1;
  if(v===false||v===0||v==="0")return 0;
  return null;
}

// Customer catalog
app.get("/api/catalog",async(q,s)=>{
  try{
    const [g,p]=await Promise.all([
      pool.query("SELECT * FROM games WHERE active=1 ORDER BY id"),
      pool.query("SELECT * FROM packages WHERE active=1 ORDER BY id")
    ]);
    s.json({games:g.rows,packages:p.rows});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Catalog load failed"});
  }
});

// Customer registration
app.post("/api/customer/register",customerLimiter,async(q,s)=>{
  try{
    const username=String(q.body.username||"").trim();
    const email=String(q.body.email||"").trim().toLowerCase();
    const password=String(q.body.password||"");

    if(username.length>64||Buffer.byteLength(password,"utf8")>72){
      return s.status(400).json({error:"Login အချက်အလက် မမှန်ကန်ပါ။"});
    }

    if(username.length<3||username.length>30||
       !/^[a-zA-Z0-9_]+$/.test(username)){
      return s.status(400).json({
        error:"Username ကို အင်္ဂလိပ်စာလုံး၊ နံပါတ်၊ _ ဖြင့် အနည်းဆုံး ၃ လုံးထည့်ပါ။"
      });
    }

    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
      return s.status(400).json({error:"မှန်ကန်သော Email ထည့်ပါ။"});
    }

    if(password.length<8||password.length>72){
      return s.status(400).json({error:"Password ကို ၈ လုံးမှ ၇၂ လုံးအတွင်း ထည့်ပါ။"});
    }

    const exists=await pool.query(
      "SELECT id FROM customers WHERE LOWER(username)=LOWER($1) OR email=$2",
      [username,email]
    );

    if(exists.rowCount){
      return s.status(409).json({
        error:"Username သို့မဟုတ် Email အသုံးပြုပြီးသားပါ။"
      });
    }

    const hash=await bcrypt.hash(password,12);
    const result=await pool.query(
      `INSERT INTO customers(username,email,password_hash,created_at)
       VALUES($1,$2,$3,NOW()) RETURNING id`,
      [username,email,hash]
    );

    startCustomerSession(q,s,result.rows[0].id);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Registration failed"});
  }
});

// Customer login
app.post("/api/customer/login",customerLimiter,async(q,s)=>{
  try{
    const email=String(q.body?.email||"").trim().toLowerCase();
    const password=String(q.body?.password||"");

    if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||
       password.length<8||password.length>72||
       Buffer.byteLength(password,"utf8")>72){
      return s.status(400).json({
        error:"Email သို့မဟုတ် Password အချက်အလက် မမှန်ကန်ပါ။"
      });
    }

    const r=await pool.query(
      "SELECT id,password_hash FROM customers WHERE email=$1",
      [email]
    );

    if(!r.rowCount||!(await bcrypt.compare(password,r.rows[0].password_hash))){
      return s.status(401).json({
        error:"Email သို့မဟုတ် Password မှားနေပါတယ်။"
      });
    }

    startCustomerSession(q,s,r.rows[0].id);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Login failed"});
  }
});

app.post("/api/customer/logout",customer,(q,s)=>{
  q.session.destroy(err=>{
    if(err){
      console.error("Admin logout session error:",err.message);
      return s.status(500).json({error:"Logout မအောင်မြင်ပါ။"});
    }
    s.clearCookie("connect.sid",{
      httpOnly:true,
      sameSite:"lax",
      secure:process.env.NODE_ENV==="production",
      path:"/"
    });
    s.json({ok:true});
  });
});

app.get("/api/customer/me",async(q,s)=>{
  try{
    if(!q.session.customerId)return s.json({loggedIn:false});

    const r=await pool.query(
      "SELECT id,username,email FROM customers WHERE id=$1",
      [q.session.customerId]
    );

    if(!r.rowCount)return s.json({loggedIn:false});

    s.json({loggedIn:true,customer:r.rows[0]});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Account load failed"});
  }
});

app.get("/api/customer/orders",customer,async(q,s)=>{
  try{
    const r=await pool.query(
      `SELECT id,game_name,package_name,price,player_id,server_id,
       payment,proof_file,status,created_at FROM orders
       WHERE customer_id=$1 ORDER BY id DESC`,
      [q.session.customerId]
    );
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Orders load failed"});
  }
});


// Private payment proof access: admin or owning customer only
app.get("/api/orders/:id/proof",async(q,s)=>{
  try{
    const id=Number(q.params.id);
    if(!Number.isSafeInteger(id)||id<1){
      return s.status(400).json({error:"Invalid order ID"});
    }

    let r;
    if(q.session?.admin){
      r=await pool.query(
        "SELECT proof_file FROM orders WHERE id=$1",
        [id]
      );
    }else if(q.session?.customerId){
      r=await pool.query(
        "SELECT proof_file FROM orders WHERE id=$1 AND customer_id=$2",
        [id,q.session.customerId]
      );
    }else{
      return s.status(401).json({error:"Login လုပ်ပါ။"});
    }

    if(!r.rowCount||!r.rows[0].proof_file){
      return s.status(404).json({error:"Screenshot မတွေ့ပါ။"});
    }

    const filename=String(r.rows[0].proof_file);
    if(path.basename(filename)!==filename){
      return s.status(404).json({error:"Screenshot မတွေ့ပါ။"});
    }

    const ext=path.extname(filename).toLowerCase();
    const types={
      ".jpg":"image/jpeg",
      ".jpeg":"image/jpeg",
      ".png":"image/png",
      ".webp":"image/webp"
    };
    if(!types[ext]){
      return s.status(404).json({error:"Invalid image type"});
    }

    s.set("Content-Type",types[ext]);
    s.set("X-Content-Type-Options","nosniff");
    s.set("Cache-Control","private, no-store");
    s.sendFile(path.join(uploadDir,filename),err=>{
      if(err&&!s.headersSent){
        s.status(err.statusCode===404?404:500)
          .json({error:"Screenshot ဖွင့်မရပါ။"});
      }
    });
  }catch(e){
    console.error(e);
    if(!s.headersSent)s.status(500).json({error:"Screenshot load failed"});
  }
});

// Secure payment proof upload
function uploadProof(q,s,n){
  upload.single("proof")(q,s,e=>{
    if(e){
      const status=e.code==="LIMIT_FILE_SIZE"?413:400;
      return s.status(status).json({
        error:e.code==="LIMIT_FILE_SIZE"
          ?"ပုံဖိုင်အရွယ်အစား 5MB ထက် မကျော်ရပါ။"
          :"ပုံဖိုင် Upload မအောင်မြင်ပါ။"
      });
    }
    n();
  });
}

async function discardUpload(file){
  if(file?.path){
    try{await fs.promises.unlink(file.path);}catch(e){}
  }
}


// Customer wallet balance
app.get("/api/customer/wallet",customer,async(q,s)=>{
  try{
    await pool.query(
      "INSERT INTO wallets(customer_id) VALUES($1) ON CONFLICT(customer_id) DO NOTHING",
      [q.session.customerId]
    );
    const r=await pool.query(
      "SELECT balance FROM wallets WHERE customer_id=$1",
      [q.session.customerId]
    );
    s.json({balance:Number(r.rows[0].balance)});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Wallet load failed"});
  }
});

// Customer deposit history
app.get("/api/customer/wallet/deposits",customer,async(q,s)=>{
  try{
    const r=await pool.query(
      `SELECT id,amount,payment_method,status,created_at,reviewed_at
       FROM wallet_deposits WHERE customer_id=$1 ORDER BY id DESC`,
      [q.session.customerId]
    );
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Deposit history load failed"});
  }
});

// Customer wallet transaction history
app.get("/api/customer/wallet/transactions",customer,async(q,s)=>{
  try{
    const r=await pool.query(
      `SELECT id,transaction_type,amount,reference_id,description,created_at
       FROM wallet_transactions WHERE customer_id=$1 ORDER BY id DESC`,
      [q.session.customerId]
    );
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Wallet history load failed"});
  }
});

// Submit wallet deposit request
app.post("/api/customer/wallet/deposits",customer,uploadProof,async(q,s)=>{
  let savedFile=null;
  try{
    if(!q.file){
      return s.status(400).json({error:"ငွေလွှဲ Screenshot တင်ပေးပါ။"});
    }

    const amount=Number(q.body.amount);
    const payment=String(q.body.payment||"");
    if(!Number.isSafeInteger(amount)||amount<5000||amount>1000000){
      await discardUpload(q.file);
      return s.status(400).json({error:"ငွေဖြည့်ပမာဏသည် 5,000 မှ 1,000,000 MMK အတွင်း ဖြစ်ရပါမည်။"});
    }
    if(!["KBZPay","WavePay"].includes(payment)){
      await discardUpload(q.file);
      return s.status(400).json({error:"KBZPay သို့မဟုတ် WavePay ရွေးပါ။"});
    }

    const head=await fs.promises.readFile(q.file.path);
    let ext="";
    if(head.length>=3&&head[0]===0xff&&head[1]===0xd8&&head[2]===0xff) ext="jpg";
    else if(head.length>=8&&head.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) ext="png";
    else if(head.length>=12&&head.toString("ascii",0,4)==="RIFF"&&head.toString("ascii",8,12)==="WEBP") ext="webp";

    if(!ext){
      await discardUpload(q.file);
      return s.status(400).json({error:"JPG, PNG သို့မဟုတ် WEBP ပုံအစစ်ကိုသာ တင်နိုင်ပါတယ်။"});
    }

    const safeName=q.file.filename+"."+ext;
    const safePath=path.join(uploadDir,safeName);
    await fs.promises.rename(q.file.path,safePath);
    q.file.filename=safeName;
    q.file.path=safePath;
    savedFile=q.file;

    await pool.query(
      "INSERT INTO wallets(customer_id) VALUES($1) ON CONFLICT(customer_id) DO NOTHING",
      [q.session.customerId]
    );

    const r=await pool.query(
      `INSERT INTO wallet_deposits(customer_id,amount,payment_method,proof_file)
       VALUES($1,$2,$3,$4) RETURNING id`,
      [q.session.customerId,amount,payment,safeName]
    );
    s.json({ok:true,depositId:r.rows[0].id});
  }catch(e){
    await discardUpload(savedFile||q.file);
    console.error(e);
    s.status(500).json({error:"Deposit request failed"});
  }
});

// Private wallet deposit screenshot
app.get("/api/wallet/deposits/:id/proof",async(q,s)=>{
  try{
    const id=Number(q.params.id);
    if(!Number.isSafeInteger(id)||id<1){
      return s.status(400).json({error:"Invalid deposit ID"});
    }
    let r;
    if(q.session?.admin){
      r=await pool.query("SELECT proof_file FROM wallet_deposits WHERE id=$1",[id]);
    }else if(q.session?.customerId){
      r=await pool.query(
        "SELECT proof_file FROM wallet_deposits WHERE id=$1 AND customer_id=$2",
        [id,q.session.customerId]
      );
    }else{
      return s.status(401).json({error:"Login လုပ်ပါ။"});
    }
    if(!r.rowCount)return s.status(404).json({error:"Screenshot မတွေ့ပါ။"});
    const filename=String(r.rows[0].proof_file);
    if(path.basename(filename)!==filename)return s.status(404).end();
    const ext=path.extname(filename).toLowerCase();
    const types={".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp"};
    if(!types[ext])return s.status(404).end();
    s.set("Content-Type",types[ext]);
    s.set("X-Content-Type-Options","nosniff");
    s.set("Cache-Control","private, no-store");
    s.sendFile(path.join(uploadDir,filename),err=>{
      if(err&&!s.headersSent)s.status(404).json({error:"Screenshot မဖွင့်နိုင်ပါ။"});
    });
  }catch(e){
    console.error(e);
    if(!s.headersSent)s.status(500).json({error:"Screenshot load failed"});
  }
});

// Place order
app.post("/api/orders",customer,async(q,s)=>{
  let client;
  let inTransaction=false;

  try{
    const {gameId,packageId,playerId,serverId}=q.body || {};
    const gid=Number(gameId);
    const pid=Number(packageId);

    if(!Number.isSafeInteger(gid)||gid<=0||
       !Number.isSafeInteger(pid)||pid<=0||
       typeof playerId!=="string"||!playerId.trim()||
       playerId.trim().length>150||
       (serverId!==undefined && (typeof serverId!=="string" || serverId.trim().length>50))){
      return s.status(400).json({error:"ဂိမ်း၊ Package နဲ့ Player ID မှန်ကန်စွာ ဖြည့်ပေးပါ။"});
    }

    client=await pool.connect();
    await client.query("BEGIN");
    inTransaction=true;

    const g=await client.query(
      "SELECT id,name FROM games WHERE id=$1 AND active=1",
      [gid]
    );
    const p=await client.query(
      "SELECT id,title,price FROM packages WHERE id=$1 AND game_id=$2 AND active=1",
      [pid,gid]
    );

    if(!g.rowCount||!p.rowCount){
      await client.query("ROLLBACK");
      inTransaction=false;
      return s.status(400).json({error:"ရွေးချယ်ထားသော Game သို့မဟုတ် Package မတွေ့ပါ။"});
    }

    const isMLBB=/mobile legends|mlbb|magic chess|mcgg/i.test(g.rows[0].name);
    if(isMLBB && (!serverId || !serverId.trim())){
      await client.query("ROLLBACK");
      inTransaction=false;
      return s.status(400).json({error:"Mobile Legends အတွက် Server ID ဖြည့်ပေးပါ။"});
    }

    const price=Number(p.rows[0].price);
    if(!Number.isSafeInteger(price)||price<=0){
      throw new Error("Invalid package price");
    }

    const customerId=q.session.customerId;

    await client.query(
      "INSERT INTO wallets(customer_id,balance) VALUES($1,0) ON CONFLICT(customer_id) DO NOTHING",
      [customerId]
    );

    const w=await client.query(
      "SELECT balance FROM wallets WHERE customer_id=$1 FOR UPDATE",
      [customerId]
    );

    if(!w.rowCount||Number(w.rows[0].balance)<price){
      await client.query("ROLLBACK");
      inTransaction=false;
      return s.status(400).json({
        code:"WALLET_INSUFFICIENT",
        error:"Wallet လက်ကျန်ငွေ မလုံလောက်ပါ။ အရင်ဆုံး Wallet ထဲသို့ ငွေဖြည့်ပေးပါ။"
      });
    }

    const debit=await client.query(
      `UPDATE wallets
       SET balance=balance-$1,updated_at=NOW()
       WHERE customer_id=$2 AND balance >= $1
       RETURNING balance`,
      [price,customerId]
    );

    if(!debit.rowCount){
      await client.query("ROLLBACK");
      inTransaction=false;
      return s.status(400).json({
        code:"WALLET_INSUFFICIENT",
        error:"Wallet လက်ကျန်ငွေ မလုံလောက်ပါ။"
      });
    }

    const order=await client.query(
      `INSERT INTO orders
       (game_name,package_name,price,player_id,server_id,contact,payment,
        proof_file,customer_id,status,created_at)
       VALUES($1,$2,$3,$4,$5,'','Wallet',NULL,$6,'Completed',NOW())
       RETURNING id`,
      [
        g.rows[0].name,
        p.rows[0].title,
        price,
        playerId.trim(),
        serverId && serverId.trim() ? serverId.trim() : null,
        customerId
      ]
    );

    await client.query(
      `INSERT INTO wallet_transactions
       (customer_id,transaction_type,amount,reference_id,description)
       VALUES($1,'PURCHASE',$2,$3,$4)`,
      [
        customerId,
        price,
        String(order.rows[0].id),
        "Game package purchase"
      ]
    );

    await client.query("COMMIT");
    inTransaction=false;

    s.json({
      ok:true,
      orderId:order.rows[0].id,
      balance:debit.rows[0].balance
    });

  }catch(e){
    if(client&&inTransaction){
      try{await client.query("ROLLBACK");}catch(_){}
    }
    console.error("Wallet purchase error:",e);
    s.status(500).json({error:"Order တင်မရပါ။ Wallet ငွေဖြတ်မှုကို စစ်ဆေးပြီး ပြန်ကြိုးစားပါ။"});
  }finally{
    if(client)client.release();
  }
});

// Admin wallet deposit management
app.get("/api/admin/wallet/deposits",admin,async(q,s)=>{
  try{
    const r=await pool.query(
      `SELECT d.id,d.customer_id,c.username,c.email,d.amount,d.payment_method,
              d.proof_file,d.status,d.created_at,d.reviewed_at
       FROM wallet_deposits d
       JOIN customers c ON c.id=d.customer_id
       ORDER BY CASE WHEN d.status='Pending' THEN 0 ELSE 1 END,d.id DESC`
    );
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Wallet deposits load failed"});
  }
});

// Approve or reject a deposit exactly once
app.patch("/api/admin/wallet/deposits/:id",admin,async(q,s)=>{
  const id=Number(q.params.id);
  const status=String(q.body.status||"");
  if(!Number.isSafeInteger(id)||id<1||!["Completed","Rejected"].includes(status)){
    return s.status(400).json({error:"Deposit အချက်အလက် မမှန်ပါ။"});
  }

  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const d=await client.query(
      "SELECT id,customer_id,amount,status FROM wallet_deposits WHERE id=$1 FOR UPDATE",
      [id]
    );
    if(!d.rowCount){
      await client.query("ROLLBACK");
      return s.status(404).json({error:"Deposit မတွေ့ပါ။"});
    }
    if(d.rows[0].status!=="Pending"){
      await client.query("ROLLBACK");
      return s.status(409).json({error:"ဒီ Deposit ကို စစ်ဆေးပြီးသားဖြစ်ပါတယ်။"});
    }

    if(status==="Completed"){
      await client.query(
        "INSERT INTO wallets(customer_id) VALUES($1) ON CONFLICT(customer_id) DO NOTHING",
        [d.rows[0].customer_id]
      );
      await client.query(
        "UPDATE wallets SET balance=balance+$1,updated_at=NOW() WHERE customer_id=$2",
        [d.rows[0].amount,d.rows[0].customer_id]
      );
      await client.query(
        `INSERT INTO wallet_transactions
         (customer_id,deposit_id,transaction_type,amount,reference_id,description)
         VALUES($1,$2,'DEPOSIT',$3,$4,$5)`,
        [d.rows[0].customer_id,id,d.rows[0].amount,String(id),"Admin completed wallet deposit"]
      );
    }

    await client.query(
      "UPDATE wallet_deposits SET status=$1,reviewed_at=NOW() WHERE id=$2",
      [status,id]
    );
    await client.query("COMMIT");
    s.json({ok:true,status});
  }catch(e){
    try{await client.query("ROLLBACK");}catch(_){}
    console.error(e);
    s.status(500).json({error:"Deposit review failed"});
  }finally{
    client.release();
  }
});

// Admin login
app.post("/api/admin/login",limiter,async(q,s)=>{
  try{
    const hash=process.env.ADMIN_PASSWORD_HASH||"";
    const username=String(q.body.username||"");
    const password=String(q.body.password||"");

    if(username.length>64||Buffer.byteLength(password,"utf8")>72){
      return s.status(400).json({error:"Login အချက်အလက် မမှန်ကန်ပါ။"});
    }

    if(username!==(process.env.ADMIN_USERNAME||"Amiga")||
       !hash||!(await bcrypt.compare(password,hash))){
      return s.status(401).json({
        error:"Username သို့မဟုတ် Password မှားနေပါတယ်။"
      });
    }

    q.session.regenerate(err=>{
      if(err)return s.status(500).json({error:"Session error"});
      q.session.admin=true;
      q.session.csrfToken=crypto.randomBytes(32).toString("hex");
      q.session.save(e=>{
        if(e)return s.status(500).json({error:"Session save error"});
        s.json({ok:true,csrfToken:q.session.csrfToken});
      });
    });
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Admin login failed"});
  }
});

app.post("/api/admin/logout",admin,(q,s)=>{
  q.session.destroy(err=>{
    if(err){
      return s.status(500).json({error:"Logout failed"});
    }
    s.clearCookie("connect.sid",{
      path:"/",
      httpOnly:true,
      sameSite:"lax",
      secure:process.env.NODE_ENV==="production"
    });
    s.json({ok:true});
  });
});

app.get("/api/admin/me",(q,s)=>{
  s.json({loggedIn:!!q.session?.admin});
});

// Admin orders
app.get("/api/admin/orders",admin,async(q,s)=>{
  try{
    const r=await pool.query("SELECT * FROM orders ORDER BY id DESC");
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Orders load failed"});
  }
});

app.patch("/api/admin/orders/:id",admin,async(q,s)=>{
  try{
    const status=q.body.status;
    if(!["Completed","Rejected"].includes(status)){
      return s.status(400).json({error:"Invalid status"});
    }

    const orderId=Number(q.params.id);
    if(!Number.isSafeInteger(orderId)||orderId<1){
      return s.status(400).json({error:"Order ID မမှန်ပါ။"});
    }
    const r=await pool.query(
      "UPDATE orders SET status=$1 WHERE id=$2 AND status='Pending' RETURNING id",
      [status,orderId]
    );
    if(!r.rowCount){
      return s.status(409).json({error:"ဒီ Order ကို စစ်ဆေးပြီးသား ဖြစ်နိုင်ပါသည်။"});
    }
    s.json({ok:true});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Order update failed"});
  }
});


// Admin customer management
app.get("/api/admin/customers",admin,async(q,s)=>{
  try{
    const r=await pool.query(`
      SELECT c.id,c.username,c.email,c.created_at,
        COUNT(o.id)::int AS order_count,
        COALESCE(SUM(o.price) FILTER (WHERE o.status='Completed'),0)::numeric AS completed_total
      FROM customers c
      LEFT JOIN orders o ON o.customer_id=c.id
      GROUP BY c.id
      ORDER BY c.id DESC
    `);
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Customers load failed"});
  }
});

app.get("/api/admin/customers/:id/orders",admin,async(q,s)=>{
  try{
    const r=await pool.query(
      `SELECT id,game_name,package_name,price,player_id,server_id,payment,status,created_at
       FROM orders WHERE customer_id=$1 ORDER BY id DESC`,
      [Number(q.params.id)]
    );
    s.json(r.rows);
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Customer orders load failed"});
  }
});


// Admin sales report
app.get("/api/admin/reports/sales",admin,async(q,s)=>{
  try{
    const [summary,daily]=await Promise.all([
      pool.query(`
        SELECT
          COUNT(*)::int AS total_orders,
          COUNT(*) FILTER (WHERE status='Pending')::int AS pending_orders,
          COUNT(*) FILTER (WHERE status='Approved')::int AS approved_orders,
          COUNT(*) FILTER (WHERE status='Rejected')::int AS rejected_orders,
          COUNT(*) FILTER (WHERE status='Completed')::int AS completed_orders,
          COALESCE(SUM(price) FILTER (WHERE status='Completed'),0)::numeric AS total_revenue,
          COALESCE(SUM(price) FILTER (WHERE status='Completed' AND created_at >= date_trunc('day',NOW())),0)::numeric AS today_revenue,
          COALESCE(SUM(price) FILTER (WHERE status='Completed' AND created_at >= date_trunc('month',NOW())),0)::numeric AS month_revenue
        FROM orders
      `),
      pool.query(`
        SELECT date_trunc('day',created_at)::date AS day,
          COALESCE(SUM(price) FILTER (WHERE status='Completed'),0)::numeric AS revenue
        FROM orders
        WHERE created_at >= NOW()-INTERVAL '6 days'
        GROUP BY date_trunc('day',created_at)::date
        ORDER BY day
      `)
    ]);
    s.json({summary:summary.rows[0],daily:daily.rows});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Sales report load failed"});
  }
});

// Admin catalog
app.get("/api/admin/catalog",admin,async(q,s)=>{
  try{
    const [g,p]=await Promise.all([
      pool.query("SELECT * FROM games ORDER BY id"),
      pool.query("SELECT * FROM packages ORDER BY id")
    ]);
    s.json({games:g.rows,packages:p.rows});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Admin catalog load failed"});
  }
});

app.post("/api/admin/games",admin,async(q,s)=>{
  try{
    const name=typeof q.body?.name==="string"?q.body.name.trim():"";
    if(!name||name.length>120||Buffer.byteLength(name,"utf8")>480){
      return s.status(400).json({error:"Game အမည်ကို မှန်ကန်စွာထည့်ပါ။ (အများဆုံး 120 လုံး)"});
    }

    const r=await pool.query(
      "INSERT INTO games(name,active) VALUES($1,1) RETURNING id",
      [name]
    );
    s.json({id:r.rows[0].id});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Game add failed"});
  }
});

app.post("/api/admin/packages",admin,async(q,s)=>{
  try{
    const gameId=Number(q.body?.gameId);
    const title=typeof q.body?.title==="string"?q.body.title.trim():"";
    const price=Number(q.body?.price);

    if(!Number.isSafeInteger(gameId)||gameId<1||gameId>2147483647||
       !title||title.length>120||Buffer.byteLength(title,"utf8")>480||
       !Number.isSafeInteger(price)||price<1||price>2147483647){
      return s.status(400).json({error:"မှန်ကန်သော Package အချက်အလက်ထည့်ပါ။"});
    }

    const game=await pool.query("SELECT id FROM games WHERE id=$1",[gameId]);
    if(!game.rowCount){
      return s.status(404).json({error:"Game မတွေ့ပါ။"});
    }

    const r=await pool.query(
      `INSERT INTO packages(game_id,title,price,active)
       VALUES($1,$2,$3,1) RETURNING id`,
      [gameId,title,price]
    );
    s.json({id:r.rows[0].id});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Package add failed"});
  }
});

app.patch("/api/admin/packages/:id/details",admin,async(q,s)=>{
  try{
    const id=Number(q.params.id);
    const title=typeof q.body?.title==="string"?q.body.title.trim():"";
    const price=Number(q.body?.price);

    if(!Number.isSafeInteger(id)||id<1||id>2147483647||
       !title||title.length>120||Buffer.byteLength(title,"utf8")>480||
       !Number.isSafeInteger(price)||price<1||price>2147483647){
      return s.status(400).json({
        error:"Package အမည်၊ ID နှင့် ဈေးနှုန်း မှန်ကန်စွာထည့်ပါ။"
      });
    }

    const r=await pool.query(
      "UPDATE packages SET title=$1,price=$2 WHERE id=$3 RETURNING id",
      [title,price,id]
    );

    if(!r.rowCount)return s.status(404).json({error:"Package မတွေ့ပါ။"});
    s.json({ok:true});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Package update failed"});
  }
});

app.patch("/api/admin/games/:id",admin,async(q,s)=>{
  try{
    const id=Number(q.params.id);
    const active=activeValue(q.body?.active);

    if(!Number.isSafeInteger(id)||id<1||id>2147483647||active===null){
      return s.status(400).json({error:"Game ID သို့မဟုတ် Active Status မမှန်ပါ။"});
    }

    const r=await pool.query(
      "UPDATE games SET active=$1 WHERE id=$2 RETURNING id",
      [active,id]
    );
    if(!r.rowCount)return s.status(404).json({error:"Game မတွေ့ပါ။"});
    s.json({ok:true});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Game update failed"});
  }
});

app.patch("/api/admin/packages/:id",admin,async(q,s)=>{
  try{
    const id=Number(q.params.id);
    const active=activeValue(q.body?.active);

    if(!Number.isSafeInteger(id)||id<1||id>2147483647||active===null){
      return s.status(400).json({error:"Package ID သို့မဟုတ် Active Status မမှန်ပါ။"});
    }

    const r=await pool.query(
      "UPDATE packages SET active=$1 WHERE id=$2 RETURNING id",
      [active,id]
    );
    if(!r.rowCount)return s.status(404).json({error:"Package မတွေ့ပါ။"});
    s.json({ok:true});
  }catch(e){
    console.error(e);
    s.status(500).json({error:"Package update failed"});
  }
});


app.get("/admin",(q,s)=>{
  s.sendFile(path.join(__dirname,"public","admin.html"));
});

async function start(){
  await pool.query("SELECT 1");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL UNIQUE REFERENCES customers(id) ON DELETE CASCADE,
      balance BIGINT NOT NULL DEFAULT 0 CHECK(balance >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_deposits (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      amount BIGINT NOT NULL CHECK(amount BETWEEN 5000 AND 1000000),
      payment_method TEXT NOT NULL CHECK(payment_method IN ('KBZPay','WavePay')),
      proof_file TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending'
        CHECK(status IN ('Pending','Approved','Rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      rejection_reason TEXT
    )
  `);

  // Wallet deposit status migration: preserve legacy Approved records.
  await pool.query(`
    ALTER TABLE wallet_deposits
    DROP CONSTRAINT IF EXISTS wallet_deposits_status_check
  `);

  await pool.query(`
    ALTER TABLE wallet_deposits
    ADD CONSTRAINT wallet_deposits_status_check
    CHECK(status IN ('Pending','Approved','Completed','Rejected'))
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      deposit_id INTEGER UNIQUE REFERENCES wallet_deposits(id),
      transaction_type TEXT NOT NULL
        CHECK(transaction_type IN ('DEPOSIT','PURCHASE','REFUND','ADJUSTMENT')),
      amount BIGINT NOT NULL CHECK(amount > 0),
      reference_id TEXT,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS wallet_deposits_customer_idx
    ON wallet_deposits(customer_id, id DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS wallet_transactions_customer_idx
    ON wallet_transactions(customer_id, id DESC)
  `);

  app.listen(Number(process.env.PORT||3000),()=>{
    console.log("MM GAME STORE PostgreSQL server ready at http://127.0.0.1:3000");
  });
}

start().catch(e=>{
  console.error("SERVER START FAILED:",e.message);
  process.exit(1);
});
