const path = require('path');
const express=require('express');
const cors=require('cors');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const crypto=require('crypto');
const {Pool}=require('pg');
require('dotenv').config();

const app=express();
app.use(cors());
app.use(express.json({limit:'100kb'}));
const hasDatabase=Boolean(process.env.DATABASE_URL);
const pool=hasDatabase ? new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.DATABASE_URL.includes('localhost') ? false : {rejectUnauthorized:false}
}) : null;

async function initDatabase(){
  if(!pool) return;
  const fs=require('fs');
  const schema=fs.readFileSync(require('path').join(__dirname,'schema.sql'),'utf8');
  await pool.query(schema);
}

function requireDatabase(req,res,next){
  if(!pool) return res.status(503).json({error:'Database is not configured on this Render service'});
  next();
}
app.use('/api/auth', requireDatabase);
app.use('/api/me', requireDatabase);
app.use('/api/deposits', requireDatabase);
app.use('/api/balance', requireDatabase);
app.use('/api/webhooks', requireDatabase);

function auth(req,res,next){
  try{
    const h=req.headers.authorization||'';
    if(!h.startsWith('Bearer ')) return res.status(401).json({error:'Authentication required'});
    req.user=jwt.verify(h.slice(7),process.env.JWT_SECRET);
    next();
  }catch(e){return res.status(401).json({error:'Invalid or expired token'});}
}
function signPayload(raw){return crypto.createHmac('sha256',process.env.DEPOSIT_WEBHOOK_SECRET||'').update(raw).digest('hex');}
function safeEq(a,b){
  const aa=Buffer.from(String(a||'')); const bb=Buffer.from(String(b||''));
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}

app.get('/api/health',async(req,res)=>{
  if(!pool) return res.status(503).json({ok:false,database:false,error:'DATABASE_URL is not configured'});
  try{await pool.query('SELECT 1');res.json({ok:true,database:true});}
  catch(e){res.status(503).json({ok:false,database:false,error:'Database connection failed'});}
});

app.post('/api/auth/register',async(req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase();
  const password=String(req.body.password||'');
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)||password.length<8)
    return res.status(400).json({error:'Use a valid email and a password of at least 8 characters'});
  try{
    const hash=await bcrypt.hash(password,12);
    const r=await pool.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email',[email,hash]);
    const user=r.rows[0];
    res.status(201).json({token:jwt.sign({id:user.id,email:user.email},process.env.JWT_SECRET,{expiresIn:'7d'}),user});
  }catch(e){res.status(409).json({error:'Email already registered'});}
});
app.post('/api/auth/login',async(req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
  const r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
  if(!r.rowCount||!(await bcrypt.compare(password,r.rows[0].password_hash))) return res.status(401).json({error:'Invalid credentials'});
  const u=r.rows[0];
  res.json({token:jwt.sign({id:u.id,email:u.email},process.env.JWT_SECRET,{expiresIn:'7d'}),user:{id:u.id,email:u.email}});
});

app.get('/api/me',auth,async(req,res)=>{
  const r=await pool.query('SELECT id,email,created_at FROM users WHERE id=$1',[req.user.id]);
  res.json(r.rows[0]);
});

/*
  Deposit addresses are intentionally provisioned by your custody/payment provider.
  This endpoint returns addresses already assigned to the user. Do not generate
  custodial private keys inside this web server.
*/
app.get('/api/deposits/addresses',auth,async(req,res)=>{
  const r=await pool.query('SELECT asset,network,deposit_address FROM wallets WHERE user_id=$1 ORDER BY asset,network',[req.user.id]);
  res.json({addresses:r.rows});
});

app.get('/api/deposits',auth,async(req,res)=>{
  const r=await pool.query(`SELECT asset,network,amount,tx_hash,confirmations,status,created_at,confirmed_at
    FROM deposits WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,[req.user.id]);
  res.json({deposits:r.rows});
});

app.get('/api/balance',auth,async(req,res)=>{
  const r=await pool.query(`SELECT asset,COALESCE(SUM(amount),0) balance
    FROM ledger_entries WHERE user_id=$1 GROUP BY asset ORDER BY asset`,[req.user.id]);
  res.json({balances:r.rows});
});

/*
  Provider webhook contract:
  POST JSON:
  {
    "event_id":"unique-provider-event-id",
    "user_id":123,
    "asset":"USDT",
    "network":"TRON",
    "amount":"100.50",
    "tx_hash":"...",
    "confirmations":20,
    "status":"confirmed",
    "deposit_address":"..."
  }
  Signature header: x-deposit-signature = HMAC-SHA256(raw_body, DEPOSIT_WEBHOOK_SECRET)
*/
app.post('/api/webhooks/deposits',async(req,res)=>{
  const signature=req.headers['x-deposit-signature'];
  const raw=JSON.stringify(req.body);
  if(!safeEq(signature,signPayload(raw))) return res.status(401).json({error:'Invalid signature'});
  const {event_id,user_id,asset,network,amount,tx_hash,confirmations=0,status='pending',deposit_address}=req.body;
  if(!event_id||!user_id||!asset||!network||!amount||!tx_hash) return res.status(400).json({error:'Incomplete deposit event'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const existing=await client.query('SELECT id,status FROM deposits WHERE provider_event_id=$1 FOR UPDATE',[event_id]);
    if(existing.rowCount){await client.query('COMMIT');return res.json({ok:true,duplicate:true});}
    const wallet=deposit_address ? await client.query(
      'SELECT id FROM wallets WHERE user_id=$1 AND asset=$2 AND network=$3 AND deposit_address=$4',
      [user_id,asset,network,deposit_address]) : {rowCount:0};
    if(deposit_address && !wallet.rowCount) throw new Error('Deposit address does not belong to user');
    const d=await client.query(`INSERT INTO deposits
      (user_id,wallet_id,asset,network,amount,tx_hash,confirmations,status,provider_event_id,confirmed_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $8='confirmed' THEN NOW() ELSE NULL END)
      RETURNING id`,[user_id,wallet.rowCount?wallet.rows[0].id:null,asset,network,amount,tx_hash,confirmations,status,event_id]);
    if(status==='confirmed'){
      await client.query(`INSERT INTO ledger_entries(user_id,asset,amount,type,reference_id)
        VALUES($1,$2,$3,'deposit',$4)`,[user_id,asset,amount,String(d.rows[0].id)]);
    }
    await client.query('COMMIT');
    res.status(201).json({ok:true,deposit_id:d.rows[0].id,credited:status==='confirmed'});
  }catch(e){
    await client.query('ROLLBACK');
    console.error(e);
    res.status(400).json({error:'Deposit event rejected'});
  }finally{client.release();}
});

/* Confirmation update from the provider. Only confirmed deposits are credited. */
app.post('/api/webhooks/deposits/confirm',async(req,res)=>{
  const signature=req.headers['x-deposit-signature'];
  if(!safeEq(signature,signPayload(JSON.stringify(req.body)))) return res.status(401).json({error:'Invalid signature'});
  const {event_id,confirmations,status}=req.body;
  if(!event_id||status!=='confirmed') return res.status(400).json({error:'Invalid confirmation'});
  const c=await pool.connect();
  try{
    await c.query('BEGIN');
    const d=await c.query('SELECT * FROM deposits WHERE provider_event_id=$1 FOR UPDATE',[event_id]);
    if(!d.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Deposit not found'});}
    const dep=d.rows[0];
    await c.query(`UPDATE deposits SET status='confirmed',confirmations=$1,confirmed_at=COALESCE(confirmed_at,NOW()) WHERE id=$2`,
      [confirmations||dep.confirmations,dep.id]);
    const exists=await c.query(`SELECT 1 FROM ledger_entries WHERE type='deposit' AND reference_id=$1`,[String(dep.id)]);
    if(!exists.rowCount) await c.query(`INSERT INTO ledger_entries(user_id,asset,amount,type,reference_id) VALUES($1,$2,$3,'deposit',$4)`,
      [dep.user_id,dep.asset,dep.amount,String(dep.id)]);
    await c.query('COMMIT');
    res.json({ok:true,credited:!exists.rowCount});
  }catch(e){await c.query('ROLLBACK');res.status(400).json({error:'Confirmation failed'});}
  finally{c.release();}
});

const opportunities=[
 {pair:'BTC/USDT',buyExchange:'Exchange A',sellExchange:'Exchange B',buy:103420,sell:103615,spread:0.188,net:14.20},
 {pair:'ETH/USDT',buyExchange:'Exchange A',sellExchange:'Exchange C',buy:4120,sell:4137,spread:0.413,net:8.73},
 {pair:'SOL/USDT',buyExchange:'Exchange B',sellExchange:'Exchange C',buy:182.41,sell:183.06,spread:0.356,net:5.18}
];
app.get('/api/opportunities',(req,res)=>res.json({updatedAt:new Date().toISOString(),opportunities}));

app.use((req,res,next)=>{
  if(req.method==='GET' && !req.path.startsWith('/api/')){
    return res.sendFile(path.join(__dirname, 'public','index.html'));
  }
  next();
});
const port=Number(process.env.PORT)||10000;
async function start(){
  try{
    if(pool){
      await initDatabase();
      console.log('Database schema ready');
    }else{
      console.warn('DATABASE_URL is not configured; frontend will load but database features are disabled');
    }
  }catch(e){
    console.error('Database initialization failed:',e.message);
  }
  app.listen(port,'0.0.0.0',()=>console.log('ArbiFlow server listening on '+port));
}
start();
