const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json({limit:'16kb'}));
const PORT = process.env.PORT || 3000;
const SECRET = process.env.PAIRING_SECRET || '';
const sessions = new Map();

function auth(req,res,next) {
  if (!SECRET || SECRET.length < 32)
    return res.status(503).json({error:'Server is not configured: set PAIRING_SECRET (32+ characters) in Render.'});
  next();
}
function cleanExpired() {
  const now = Date.now();
  for (const [code,s] of sessions) if (s.expiresAt <= now) sessions.delete(code);
}
function safeEqual(a,b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) return false;
  const aa=Buffer.from(a), bb=Buffer.from(b);
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
app.get('/',(req,res)=>res.type('text').send('ParentGuard Remote signaling service is running.'));
app.get('/health',(req,res)=>res.json({ok:true,service:'parentguard-remote-signaling',version:2}));
app.post('/api/session',auth,(req,res)=>{
  cleanExpired();
  let code;
  do { code=String(crypto.randomInt(100000,1000000)); } while(sessions.has(code));
  const hostToken=crypto.randomBytes(32).toString('hex');
  sessions.set(code,{hostToken,controllerToken:null,createdAt:Date.now(),expiresAt:Date.now()+10*60*1000,state:'waiting'});
  res.json({ok:true,code,expiresInSeconds:600,hostToken});
});
app.post('/api/connect',auth,(req,res)=>{
  cleanExpired();
  const code=String(req.body && req.body.code || '').replace(/\s/g,'');
  const s=sessions.get(code);
  if(!s) return res.status(404).json({error:'Pairing code not found or expired.'});
  if(s.state!=='waiting') return res.status(409).json({error:'This code already has a pending or completed request.'});
  s.controllerToken=crypto.randomBytes(32).toString('hex');
  s.state='pending';
  res.json({ok:true,state:'pending',message:'Request sent. Approve it on the host device.',controllerToken:s.controllerToken});
});
app.get('/api/session/status',auth,(req,res)=>{
  cleanExpired();
  const s=sessions.get(String(req.query.code||''));
  if(!s) return res.status(404).json({error:'Session expired or not found.'});
  if(!safeEqual(String(req.headers['x-host-token']||''),s.hostToken)) return res.status(403).json({error:'Invalid host token.'});
  res.json({ok:true,state:s.state,expiresAt:s.expiresAt});
});
app.post('/api/session/respond',auth,(req,res)=>{
  cleanExpired();
  const s=sessions.get(String(req.body && req.body.code || ''));
  if(!s) return res.status(404).json({error:'Session expired or not found.'});
  if(!safeEqual(String(req.headers['x-host-token']||''),s.hostToken)) return res.status(403).json({error:'Invalid host token.'});
  if(s.state!=='pending') return res.status(409).json({error:'There is no pending request to respond to.'});
  s.state=req.body && req.body.approve===true ? 'connected' : 'rejected';
  res.json({ok:true,state:s.state});
});
app.get('/api/connect/status',auth,(req,res)=>{
  cleanExpired();
  const s=sessions.get(String(req.query.code||''));
  if(!s) return res.status(404).json({error:'Session expired or not found.'});
  if(!safeEqual(String(req.headers['x-controller-token']||''),s.controllerToken)) return res.status(403).json({error:'Invalid controller token.'});
  res.json({ok:true,state:s.state});
});
app.post('/api/session/end',auth,(req,res)=>{
  const s=sessions.get(String(req.body && req.body.code || ''));
  if(!s) return res.json({ok:true});
  const host=safeEqual(String(req.headers['x-host-token']||''),s.hostToken);
  const controller=safeEqual(String(req.headers['x-controller-token']||''),s.controllerToken);
  if(!host&&!controller) return res.status(403).json({error:'Invalid session token.'});
  sessions.delete(String(req.body.code));
  res.json({ok:true});
});
app.listen(PORT,()=>console.log(`ParentGuard Remote signaling API listening on ${PORT}`));
