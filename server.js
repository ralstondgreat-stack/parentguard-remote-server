const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json({limit:'256kb'}));
const PORT = process.env.PORT || 3000;
const SECRET = process.env.PAIRING_SECRET || '';
const sessions = new Map();
function auth(req,res,next) {
  if (!SECRET || SECRET.length < 32) return res.status(503).json({error:'Server is not configured: set PAIRING_SECRET (32+ characters) in Render.'});
  next();
}
function cleanExpired() { const now=Date.now(); for (const [code,s] of sessions) if(s.expiresAt<=now) sessions.delete(code); }
function safeEqual(a,b) { if(typeof a!=='string'||typeof b!=='string'||!a||!b)return false;const aa=Buffer.from(a),bb=Buffer.from(b);return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb); }
function getSession(req,res,role) {
  cleanExpired(); const code=String((req.body&&req.body.code)||req.query.code||''); const s=sessions.get(code);
  if(!s){res.status(404).json({error:'Session expired or not found.'});return null;}
  const token=String(req.headers[role==='host'?'x-host-token':'x-controller-token']||'');
  const expected=role==='host'?s.hostToken:s.controllerToken;
  if(!safeEqual(token,expected)){res.status(403).json({error:'Invalid session token.'});return null;}
  if(s.state!=='connected'){res.status(409).json({error:'Host approval is required before signaling.'});return null;}
  return {code,s};
}
app.get('/',(req,res)=>res.type('text').send('ParentGuard Remote signaling service is running.'));
app.get('/health',(req,res)=>res.json({ok:true,service:'parentguard-remote-signaling',version:3,features:['pairing','approval','webrtc-signaling','touch-command-queue']}));
app.post('/api/session',auth,(req,res)=>{cleanExpired();let code;do{code=String(crypto.randomInt(100000,1000000));}while(sessions.has(code));const hostToken=crypto.randomBytes(32).toString('hex');sessions.set(code,{hostToken,controllerToken:null,createdAt:Date.now(),expiresAt:Date.now()+10*60*1000,state:'waiting',signals:{host:[],controller:[]},touchQueue:[]});res.json({ok:true,code,expiresInSeconds:600,hostToken});});
app.post('/api/connect',auth,(req,res)=>{cleanExpired();const code=String(req.body&&req.body.code||'').replace(/\s/g,'');const s=sessions.get(code);if(!s)return res.status(404).json({error:'Pairing code not found or expired.'});if(s.state!=='waiting')return res.status(409).json({error:'This code already has a pending or completed request.'});s.controllerToken=crypto.randomBytes(32).toString('hex');s.state='pending';res.json({ok:true,state:'pending',message:'Request sent. Approve it on the host device.',controllerToken:s.controllerToken});});
app.get('/api/session/status',auth,(req,res)=>{cleanExpired();const s=sessions.get(String(req.query.code||''));if(!s)return res.status(404).json({error:'Session expired or not found.'});if(!safeEqual(String(req.headers['x-host-token']||''),s.hostToken))return res.status(403).json({error:'Invalid host token.'});res.json({ok:true,state:s.state,expiresAt:s.expiresAt});});
app.post('/api/session/respond',auth,(req,res)=>{cleanExpired();const code=String(req.body&&req.body.code||'');const s=sessions.get(code);if(!s)return res.status(404).json({error:'Session expired or not found.'});if(!safeEqual(String(req.headers['x-host-token']||''),s.hostToken))return res.status(403).json({error:'Invalid host token.'});if(s.state!=='pending')return res.status(409).json({error:'There is no pending request to respond to.'});s.state=req.body&&req.body.approve===true?'connected':'rejected';res.json({ok:true,state:s.state});});
app.get('/api/connect/status',auth,(req,res)=>{cleanExpired();const s=sessions.get(String(req.query.code||''));if(!s)return res.status(404).json({error:'Session expired or not found.'});if(!safeEqual(String(req.headers['x-controller-token']||''),s.controllerToken))return res.status(403).json({error:'Invalid session token.'});res.json({ok:true,state:s.state});});
// Authenticated polling-based WebRTC signaling. Payloads are bounded and never accepted before host approval.
app.post('/api/webrtc/signal',auth,(req,res)=>{const role=req.body&&req.body.role;if(role!=='host'&&role!=='controller')return res.status(400).json({error:'role must be host or controller'});const found=getSession(req,res,role);if(!found)return;const type=String(req.body.type||'');const payload=req.body.payload;if(!['offer','answer','ice','hangup'].includes(type))return res.status(400).json({error:'Unsupported signal type.'});if(type==='hangup'){found.s.state='connected';found.s.signals={host:[],controller:[]};found.s.touchQueue=[];}else{const queue=found.s.signals[role==='host'?'controller':'host'];if(queue.length>=200)return res.status(429).json({error:'Signaling queue full.'});queue.push({from:role,type,payload,at:Date.now()});}res.json({ok:true});});
app.get('/api/webrtc/signals',auth,(req,res)=>{const role=String(req.query.role||'');if(role!=='host'&&role!=='controller')return res.status(400).json({error:'role must be host or controller'});const found=getSession(req,res,role);if(!found)return;const queue=found.s.signals[role];const items=queue.splice(0,40);res.json({ok:true,items});});
// Touch input is queued only for the host, and only while the approved session is active.
app.post('/api/control/touch',auth,(req,res)=>{const found=getSession(req,res,'controller');if(!found)return;const x=Number(req.body.x),y=Number(req.body.y),action=String(req.body.action||'');if(!Number.isFinite(x)||!Number.isFinite(y)||x<0||x>1||y<0||y>1||!['tap','swipe'].includes(action))return res.status(400).json({error:'Invalid touch command.'});if(found.s.touchQueue.length>=100)return res.status(429).json({error:'Touch queue full.'});found.s.touchQueue.push({x,y,action,at:Date.now()});res.json({ok:true});});
app.get('/api/control/touch',auth,(req,res)=>{const found=getSession(req,res,'host');if(!found)return;const items=found.s.touchQueue.splice(0,20);res.json({ok:true,items});});
app.post('/api/session/end',auth,(req,res)=>{const code=String(req.body&&req.body.code||'');const s=sessions.get(code);if(!s)return res.json({ok:true});const host=safeEqual(String(req.headers['x-host-token']||''),s.hostToken);const controller=safeEqual(String(req.headers['x-controller-token']||''),s.controllerToken);if(!host&&!controller)return res.status(403).json({error:'Invalid session token.'});sessions.delete(code);res.json({ok:true});});
app.listen(PORT,()=>console.log(`ParentGuard Remote signaling API v3 listening on ${PORT}`));
