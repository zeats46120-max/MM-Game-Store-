MM GAME STORE Android MVP
ဒီဗားရှင်းမှာ better-sqlite3 မသုံးတော့ပါ။ Android Termux မှာ Native Database compile မလိုပါ။
Install: npm install
Start: npm start
Admin username: Amiga
Password hash ကို .env ထဲမှာသာထားပါ။ Password ကို Chat ထဲမပို့ပါနှင့်။
ဒီဗားရှင်းသည် ဖုန်းထဲ Local testing အတွက်သာဖြစ်သည်။ JSON data.json တွင် order/game/package သိမ်းသည်။ Session သည် memory-only ဖြစ်၍ server restart လုပ်လျှင် Admin ပြန် login ဝင်ရမည်။ Public production မတင်မီ database, durable session store, CSRF, HTTPS, backup နှင့် security review လိုအပ်သည်။
