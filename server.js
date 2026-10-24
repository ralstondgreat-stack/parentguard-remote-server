const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json({limit:'64kb'}));
const PORT = process.env.PORT || 3000;
const SECRET = process.env.PAIRING_SECRET || '';
const sessions = new Map();
function auth(req,res,next) {
  if (!SECRET || SECRET.length < 32) return res.status(503).json({error:'Set PAIRING_SECRET to a random value of at least 32 characters in Render.'});
  next();
}
function cleanExpired() {
  const now=Date.now();
  for (const [k,v] of sessions) if(v.expiresAt < now) sessions.delete(k);
}
app.get('/',(req,res)=>res.type('text').send('ParentGuard Remote signaling service is running.'));
app.get('/health',(req,res)=>res.json({ok:true,service:'parentguard-remote-signaling'}));
app.post('/api/session',auth,(req,res)=>{
  cleanExpired();
  let code;
  do { code=String(crypto.randomInt(100000,999999)); } while(sessions.has(code));
  const token=crypto.randomBytes(24).toString('hex');
  sessions.set(code,{token,createdAt:Date.now(),expiresAt:Date.now()+10*60*1000,connected:false});
  res.json({code,expiresInSeconds:600,sessionToken:token});
});
app.post('/api/connect',auth,(req,res)=>{
  cleanExpired();
  const code=String(req.body && req.body.code || '');
  const s=sessions.get(code);
  if(!s) return res.status(404).json({error:'Pairing code not found or expired.'});
  s.connected=true;
  res.json({ok:true,message:'Pairing code accepted. This starter does not yet establish a media session.'});
});
app.listen(PORT,()=>console.log(`ParentGuard Remote signaling API listening on ${PORT}`));
