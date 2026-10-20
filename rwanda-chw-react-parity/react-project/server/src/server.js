import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { pool } from './db.js';
import { auth, allow, signUser, verifyPassword, signCsrf, verifyCsrf } from './auth.js';
import { audit } from './audit.js';

dotenv.config();
const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173' }));
app.use(express.json({ limit: '4mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500, standardHeaders: true }));

const resources = {
  provinces: { table: 'provinces', permission: 'location.view', scope: null },
  districts: { table: 'districts', permission: 'location.view', scope: null },
  sectors: { table: 'sectors', permission: 'location.view', scope: null },
  cells: { table: 'cells', permission: 'location.view', scope: null },
  villages: { table: 'villages', permission: 'location.view', scope: null },
  facilities: { table: 'facilities', permission: 'facility.view', scope: 'facility' },
  chws: { table: 'chws', permission: 'chw.view', scope: 'chw' },
  households: { table: 'households', permission: 'household.view', scope: 'chw' },
  visits: { table: 'visits', permission: 'visit.view', scope: 'chw' },
  referrals: { table: 'referrals', permission: 'referral.view', scope: 'chwFacility' },
  'education-sessions': { table: 'education_sessions', permission: 'education.view', scope: 'chw' },
  'community-events': { table: 'community_events', permission: 'event.view', scope: 'event' },
  notifications: { table: 'notifications', permission: 'dashboard.view', scope: 'notification' },
  'audit-logs': { table: 'audit_logs', permission: 'audit.view', scope: 'audit' },
  users: { table: 'users', permission: 'user.view', scope: null },
};

const permissions = {
  system_admin: ['*'],
  national_admin: ['dashboard.view','report.view','report.review','chw.view','chw.create','household.view','household.create','visit.view','referral.view','education.view','event.view','analytics.view','user.view','facility.view','location.view','audit.view','import.use'],
  provincial_officer: ['dashboard.view','report.view','report.review','chw.view','chw.create','household.view','household.create','visit.view','referral.view','education.view','event.view','analytics.view','facility.view','location.view'],
  district_officer: ['dashboard.view','report.view','report.review','chw.view','chw.create','household.view','household.create','visit.view','referral.view','education.view','event.view','analytics.view','facility.view','location.view'],
  sector_supervisor: ['dashboard.view','report.view','report.review','chw.view','household.view','household.create','visit.view','referral.view','education.view','event.view','location.view'],
  facility_admin: ['dashboard.view','report.view','report.review','chw.view','household.view','visit.view','referral.view','education.view','event.view','facility.view'],
  facility_staff: ['dashboard.view','report.view','referral.view','education.view','event.view','facility.view'],
  chw: ['dashboard.view','report.view','report.create','report.submit','household.view','household.create','visit.view','visit.create','referral.view','referral.create','education.view','education.create','event.view','event.create'],
  data_clerk: ['dashboard.view','report.view','report.create','report.submit','household.view','household.create','visit.view','referral.view','education.view','event.view','import.use'],
  me_officer: ['dashboard.view','report.view','report.review','education.view','event.view','analytics.view','audit.view','location.view'],
  auditor: ['dashboard.view','report.view','education.view','event.view','analytics.view','audit.view','location.view'],
};
const can = (u, p) => !!u && ((permissions[u.role] || []).includes('*') || (permissions[u.role] || []).includes(p));
const writePermissions = {
  chws: 'chw.create', households: 'household.create', visits: 'visit.create', referrals: 'referral.create',
  'education-sessions': 'education.create', 'community-events': 'event.create',
};
const protectedColumns = new Set(['created_at','updated_at','last_login_at','submitted_at','reviewed_at','reviewed_by','timestamp']);
const fieldAliases = {
  visits: { date: 'visit_date' },
  referrals: { date: 'referral_date' },
  'education-sessions': { date: 'session_date' },
  'community-events': { date: 'event_date' },
};
const outputAliases = {
  visits: { visit_date: 'date' },
  referrals: { referral_date: 'date' },
  'education-sessions': { session_date: 'date' },
  'community-events': { event_date: 'date' },
};

function publicUser(u) { const { password_hash, ...safe } = u; return safe; }
function mapOut(resource, row) {
  const aliases = outputAliases[resource] || {};
  const out = { ...row };
  if (resource === 'users') delete out.password_hash;
  for (const [db, api] of Object.entries(aliases)) { if (out[db] !== undefined) { out[api] = out[db]; delete out[db]; } }
  if (resource === 'notifications' && out.read_flag !== undefined) { out.read = !!out.read_flag; delete out.read_flag; }
  return out;
}
function mapIn(resource, body) {
  const out = { ...body };
  for (const [api, db] of Object.entries(fieldAliases[resource] || {})) { if (out[api] !== undefined) { out[db] = out[api]; delete out[api]; } }
  if (resource === 'notifications' && out.read !== undefined) { out.read_flag = out.read ? 1 : 0; delete out.read; }
  return out;
}
function csrfRequired(req) {
  if (!['POST','PUT','PATCH','DELETE'].includes(req.method)) return true;
  const token = req.headers['x-csrf-token'];
  if (!token || !verifyCsrf(token, req.user.id)) return false;
  return true;
}
function requireCsrf(req, res, next) { if (!csrfRequired(req)) return res.status(403).json({ error: 'Invalid CSRF token' }); next(); }
function roleScopeField(role) { return ({ provincial_officer:'province_id', district_officer:'district_id', sector_supervisor:'sector_id', facility_admin:'facility_id', facility_staff:'facility_id', data_clerk:'district_id' })[role] || null; }
async function chwIdsForUser(u) {
  if (u.role === 'chw') {
    const [rows] = await pool.query('SELECT id FROM chws WHERE LOWER(email)=LOWER(?) OR (LOWER(first_name)=LOWER(?) AND LOWER(last_name)=LOWER(?)) LIMIT 1', [u.email, u.name.split(/\s+/)[0] || '', u.name.split(/\s+/).slice(1).join(' ') || '']);
    return rows.length ? [String(rows[0].id)] : [];
  }
  const field = roleScopeField(u.role);
  if (!field) return null;
  if (!u[field]) return [];
  const [rows] = await pool.query(`SELECT id FROM chws WHERE \`${field}\`=?`, [u[field]]);
  return rows.map(x => String(x.id));
}
async function scopeWhere(resource, u) {
  const cfg = resources[resource];
  if (!cfg?.scope) return { sql: '', params: [] };
  if (resource === 'facilities' && u.facility_id) return { sql: ' WHERE id=?', params: [u.facility_id] };
  if (resource === 'notifications') return { sql: ' WHERE user_id=?', params: [u.id] };
  if (resource === 'audit-logs') return can(u, 'audit.view') ? { sql: '', params: [] } : { sql: ' WHERE user_id=?', params: [u.id] };
  const ids = await chwIdsForUser(u);
  if (ids === null) return { sql: '', params: [] };
  if (!ids.length) return { sql: ' WHERE 1=0', params: [] };
  if (resource === 'chws') return { sql: ` WHERE id IN (${ids.map(()=>'?' ).join(',')})`, params: ids };
  const owner = resource === 'community-events' ? 'organizing_chw_id' : 'chw_id';
  let sql = ` WHERE ${owner} IN (${ids.map(()=>'?' ).join(',')})`;
  const params = [...ids];
  if (resource === 'referrals' && u.facility_id) { sql += ' OR facility_id=?'; params.push(u.facility_id); }
  return { sql, params };
}
function normalizeCreateId(resource, body) {
  if (body.id) return String(body.id);
  const prefix = ({chws:'CHW',households:'HH',visits:'VIS',referrals:'REF','education-sessions':'EDU','community-events':'EVT'})[resource] || resource.slice(0,3).toUpperCase();
  return `${prefix}-${Date.now()}-${randomBytes(2).toString('hex')}`;
}
function sanitizeFields(resource, body) {
  const allowedByResource = {
    chws:['first_name','last_name','gender','date_of_birth','phone','email','nationality','province_id','district_id','sector_id','cell_id','village_id','facility_id','supervisor_id','date_joined','status','training_status','last_reporting_date'],
    households:['village_id','cell_id','sector_id','district_id','province_id','head_reference','household_size','vulnerability','chw_id','registration_date','last_visit','follow_up_required','status'],
    visits:['visit_date','chw_id','household_id','visit_type','reason','observations','health_education_provided','referral_required','follow_up_required','follow_up_date','notes','status'],
    referrals:['referral_date','chw_id','household_id','client_reference','reason_category','facility_id','urgency','status','facility_response','outcome','follow_up_required','follow_up_date'],
    'education-sessions':['session_date','location','topic','participants','female_participants','male_participants','youth_participants','target_group','duration_minutes','chw_id','notes'],
    'community-events':['event_date','location','event_type','participants','organizing_chw_id','description','follow_up_required'],
  }[resource];
  if (!allowedByResource) return body;
  return Object.fromEntries(Object.entries(body).filter(([k]) => allowedByResource.includes(k) || k === 'id'));
}
function normalizeOptionalReferences(resource, body) {
  if (resource === 'chws') {
    for (const field of ['province_id','district_id','sector_id','cell_id','village_id','facility_id','supervisor_id']) {
      if (body[field] === '') body[field] = null;
    }
  }
  return body;
}
async function constrainBody(resource, body, u) {
  const b = { ...body };
  if (u.role === 'chw') {
    const ids = await chwIdsForUser(u); const chwId = ids?.[0];
    if (['visits','referrals','education-sessions'].includes(resource)) b.chw_id = chwId;
    if (resource === 'community-events') b.organizing_chw_id = chwId;
    if (resource === 'chws' && chwId) {
      const [r] = await pool.query('SELECT province_id,district_id,sector_id,cell_id,village_id,facility_id FROM chws WHERE id=?', [chwId]);
      Object.assign(b, r[0] || {});
    }
    if (resource === 'households' && chwId) {
      b.chw_id = chwId;
      const [r] = await pool.query('SELECT province_id,district_id,sector_id,cell_id,village_id,facility_id FROM chws WHERE id=?', [chwId]); Object.assign(b, r[0] || {});
    }
  } else {
    const field = roleScopeField(u.role);
    if (field && ['chws','households'].includes(resource)) b[field] = u[field] || null;
  }
  return b;
}

app.get('/api/health', async (_req,res) => { try { await pool.query('SELECT 1'); res.json({ok:true,database:true}); } catch(e) { res.status(503).json({ok:false,database:false,message:e.message}); } });

app.post('/api/auth/login', async (req,res) => {
  const v = z.object({ email:z.string().email(), password:z.string().min(6) }).safeParse(req.body);
  if (!v.success) return res.status(400).json({error:'Valid email and password are required'});
  const [rows] = await pool.query('SELECT * FROM users WHERE LOWER(email)=LOWER(?) AND status=\'active\' LIMIT 1', [v.data.email.trim()]);
  const u = rows[0];
  if (!u || !(await verifyPassword(v.data.password, u.password_hash))) return res.status(401).json({error:'Invalid credentials'});
  await pool.query('UPDATE users SET last_login_at=NOW() WHERE id=?', [u.id]).catch(()=>{});
  await audit(u.id,'LOGIN','users',u.id,'User logged in');
  res.json({ user:publicUser(u), token:signUser(u), csrf:signCsrf(u.id) });
});
app.post('/api/auth/register-chw', async (req,res) => {
  const v = z.object({
    first_name:z.string().trim().min(1).max(100),
    last_name:z.string().trim().min(1).max(100),
    email:z.string().trim().email().max(190),
    password:z.string().min(6).max(72),
  }).safeParse(req.body);
  if (!v.success) return res.status(400).json({error:'Enter your name, a valid email, and a password of at least 6 characters'});
  const {first_name,last_name,email,password}=v.data;
  const userId=`USR-${Date.now()}-${randomBytes(3).toString('hex')}`;
  const chwId=`CHW-${Date.now()}-${randomBytes(3).toString('hex')}`;
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('INSERT INTO users (id,email,name,role,status,password_hash) VALUES (?,?,?,\'chw\',\'pending\',?)',[userId,email,`${first_name} ${last_name}`,await bcrypt.hash(password,12)]);
    await conn.query('INSERT INTO chws (id,first_name,last_name,email,date_joined,status) VALUES (?,?,?,?,CURRENT_DATE,\'pending\')',[chwId,first_name,last_name,email]);
    await conn.commit();
    res.status(201).json({message:'Account created. A system administrator must activate it before you can sign in.'});
  } catch(e) {
    await conn.rollback();
    res.status(e.code==='ER_DUP_ENTRY'?409:422).json({error:e.code==='ER_DUP_ENTRY'?'An account with this email already exists':'Unable to create the CHW account'});
  } finally { conn.release(); }
});
app.post('/api/users/:id/activate', auth, requireCsrf, allow('system_admin'), async (req,res) => {
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows]=await conn.query("SELECT id,email FROM users WHERE id=? AND role='chw' AND status='pending' FOR UPDATE",[req.params.id]);
    if (!rows[0]) { await conn.rollback(); return res.status(404).json({error:'Pending CHW account not found'}); }
    await conn.query("UPDATE users SET status='active' WHERE id=?",[req.params.id]);
    await conn.query("UPDATE chws SET status='active' WHERE LOWER(email)=LOWER(?)",[rows[0].email]);
    await conn.commit();
    await audit(req.user.id,'ACTIVATE','users',req.params.id,'Activated CHW account');
    res.json({message:'CHW account activated'});
  } catch(e) { await conn.rollback(); res.status(500).json({error:'Unable to activate the CHW account'}); }
  finally { conn.release(); }
});
app.post('/api/auth/logout', auth, requireCsrf, async (req,res) => { await audit(req.user.id,'LOGOUT','users',req.user.id,'User logged out'); res.json({message:'Logged out'}); });
app.get('/api/auth/me', auth, (req,res) => res.json({user:publicUser(req.user),csrf:signCsrf(req.user.id)}));

app.get('/api/preferences', auth, async (req,res) => {
  const [rows] = await pool.query('SELECT reduce_motion,high_contrast,language FROM user_preferences WHERE user_id=?', [req.user.id]);
  res.json({data:rows[0] || {reduce_motion:0,high_contrast:0,language:'en'}});
});
app.post('/api/preferences', auth, requireCsrf, async (req,res) => {
  const language = ['en','rw','fr'].includes(req.body.language) ? req.body.language : 'en';
  await pool.query(`INSERT INTO user_preferences (user_id,reduce_motion,high_contrast,language) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE reduce_motion=VALUES(reduce_motion),high_contrast=VALUES(high_contrast),language=VALUES(language)`, [req.user.id,!!req.body.reduce_motion,!!req.body.high_contrast,language]);
  await audit(req.user.id,'UPDATE','user_preferences',req.user.id,'Updated accessibility and language preferences');
  res.json({data:{reduce_motion:!!req.body.reduce_motion,high_contrast:!!req.body.high_contrast,language},message:'Preferences saved.'});
});

app.get('/api/dashboard', auth, async (req,res) => {
  if (!can(req.user,'dashboard.view')) return res.status(403).json({error:'Forbidden'});
  const ids = await chwIdsForUser(req.user); const scoped = ids !== null;
  const count = async (table, field=null, extra='') => { if (!scoped) { const [[r]] = await pool.query(`SELECT COUNT(*) n FROM ${table}${extra}`); return Number(r.n); } if (!ids.length) return 0; const marks=ids.map(()=>'?').join(','); const [[r]]=await pool.query(`SELECT COUNT(*) n FROM ${table} WHERE ${field} IN (${marks})${extra.replace(/^ WHERE /,' AND ')}`,ids); return Number(r.n); };
  const stats = { active_chws: await count('chws', 'id', ' WHERE status="active"'), reports_submitted: await count('reports','chw_id',' WHERE status<>"DRAFT"'), pending_review: await count('reports','chw_id',' WHERE status IN ("SUBMITTED","UNDER_REVIEW")'), households_visited: await count('visits','chw_id'), referrals: await count('referrals','chw_id'), education_sessions: await count('education_sessions','chw_id') };
  if (req.user.facility_id && scoped) { const [[r]]=await pool.query(`SELECT COUNT(*) n FROM referrals WHERE facility_id=? OR chw_id IN (${ids.map(()=>'?').join(',')})`,[req.user.facility_id,...ids]); stats.referrals=Number(r.n); }
  res.json({stats});
});

app.get('/api/:resource', auth, async (req,res,next) => {
  const resource=req.params.resource; if(resource==='import'||resource==='reports') return next();
  const cfg=resources[resource]; if(!cfg) return res.status(404).json({error:'Route not found'});
  if(!can(req.user,cfg.permission)) return res.status(403).json({error:'Forbidden'});
  const scope=await scopeWhere(resource,req.user); const limit=Math.min(Math.max(Number(req.query.limit)||500,1),1000); const offset=Math.max(Number(req.query.offset)||0,0);
  try { const [rows]=await pool.query(`SELECT * FROM \`${cfg.table}\`${scope.sql} ORDER BY 1 LIMIT ? OFFSET ?`,[...scope.params,limit,offset]); res.json({data:rows.map(r=>mapOut(resource,r)),count:rows.length,limit,offset}); } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/:resource', auth, requireCsrf, async (req,res,next) => { if(req.params.resource==='reports'||req.params.resource==='import') return next(); return crudCreate(req,res); });
app.put('/api/:resource/:id', auth, requireCsrf, async (req,res,next) => { if(req.params.resource==='reports') return next(); return crudUpdate(req,res); });
app.patch('/api/:resource/:id', auth, requireCsrf, async (req,res,next) => { if(req.params.resource==='reports') return next(); return crudUpdate(req,res); });
app.delete('/api/:resource/:id', auth, requireCsrf, async (req,res,next) => { if(req.params.resource==='reports') return next(); return crudDelete(req,res); });

async function crudCreate(req,res) {
  const resource=req.params.resource,cfg=resources[resource],perm=writePermissions[resource]; if(!cfg||!perm) return res.status(404).json({error:'Resource cannot be created here'}); if(!can(req.user,perm)) return res.status(403).json({error:'Forbidden'});
  let b=mapIn(resource,req.body); b=normalizeOptionalReferences(resource,await constrainBody(resource,sanitizeFields(resource,b),req.user)); b.id=normalizeCreateId(resource,b);
  if (resource==='notifications'||resource==='users'||resource==='audit-logs') return res.status(403).json({error:'Resource cannot be created here'});
  try { const keys=Object.keys(b).filter(k=>!protectedColumns.has(k)); const vals=keys.map(k=>b[k]); await pool.query(`INSERT INTO \`${cfg.table}\` (${keys.map(k=>`\`${k}\``).join(',')}) VALUES (${keys.map(()=>'?').join(',')})`,vals); await audit(req.user.id,'CREATE',resource,b.id,'Created record'); const [rows]=await pool.query(`SELECT * FROM \`${cfg.table}\` WHERE id=?`,[b.id]); res.status(201).json(mapOut(resource,rows[0])); } catch(e) { res.status(422).json({error:e.code==='ER_DUP_ENTRY'?'Record already exists':e.code==='ER_NO_REFERENCED_ROW_2'?'The selected location or supervisor does not exist. Choose a valid ID.':e.message}); }
}
async function crudUpdate(req,res) {
  const resource=req.params.resource,cfg=resources[resource],perm=writePermissions[resource]; if(!cfg||!perm||['users','audit-logs'].includes(resource)) return res.status(404).json({error:'Resource cannot be updated here'}); if(!can(req.user,perm) && !(resource==='reports'&&can(req.user,'report.review'))) return res.status(403).json({error:'Forbidden'});
  let b=mapIn(resource,sanitizeFields(resource,req.body)); b=normalizeOptionalReferences(resource,await constrainBody(resource,b,req.user)); delete b.id;
  const keys=Object.keys(b).filter(k=>!protectedColumns.has(k)); if(!keys.length) return res.status(400).json({error:'No fields supplied'});
  const scope=await scopeWhere(resource,req.user); let where='id=?'; let params=[...keys.map(k=>b[k]),req.params.id]; if(scope.sql) { const [scopedRows]=await pool.query(`SELECT id FROM \`${cfg.table}\`${scope.sql} AND id=?`,[...scope.params,req.params.id]); if(!scopedRows.length)return res.status(404).json({error:'Record not found in your assigned scope'}); }
  try { await pool.query(`UPDATE \`${cfg.table}\` SET ${keys.map(k=>`\`${k}\`=?`).join(',')} WHERE ${where}`,params); const [rows]=await pool.query(`SELECT * FROM \`${cfg.table}\` WHERE id=?`,[req.params.id]); if(!rows[0])return res.status(404).json({error:'Record not found'}); await audit(req.user.id,'UPDATE',resource,req.params.id,'Updated record'); res.json(mapOut(resource,rows[0])); } catch(e){res.status(422).json({error:e.code==='ER_NO_REFERENCED_ROW_2'?'The selected location or supervisor does not exist. Choose a valid ID.':e.message});}
}
async function crudDelete(req,res) {
  const resource=req.params.resource,cfg=resources[resource]; if(!cfg||!['system_admin','national_admin','provincial_officer','district_officer'].includes(req.user.role)) return res.status(403).json({error:'Forbidden'});
  const scope=await scopeWhere(resource,req.user); try { let where='id=?'; const params=[req.params.id]; if(scope.sql){const [r]=await pool.query(`SELECT id FROM \`${cfg.table}\`${scope.sql} AND id=?`,[...scope.params,req.params.id]);if(!r.length)return res.status(404).json({error:'Record not found'});} const [r]=await pool.query(`DELETE FROM \`${cfg.table}\` WHERE ${where}`,params); if(!r.affectedRows)return res.status(404).json({error:'Record not found'}); await audit(req.user.id,'DELETE',resource,req.params.id,'Deleted record'); res.status(204).end(); }catch(e){res.status(422).json({error:e.message});}
}

app.get('/api/reports', auth, async (req,res)=>{ if(!can(req.user,'report.view'))return res.status(403).json({error:'Forbidden'}); const ids=await chwIdsForUser(req.user); let sql='SELECT r.*,CONCAT(c.first_name," ",c.last_name) chw_name FROM reports r JOIN chws c ON c.id=r.chw_id'; const params=[]; if(ids!==null){if(!ids.length)return res.json({data:[]});sql+=` WHERE r.chw_id IN (${ids.map(()=>'?').join(',')})`;params.push(...ids);} sql+=' ORDER BY r.updated_at DESC'; const [rows]=await pool.query(sql,params);res.json({data:rows}); });
app.post('/api/reports', auth, requireCsrf, async (req,res)=>{ if(!can(req.user,'report.create'))return res.status(403).json({error:'Forbidden'}); const d=req.body; const period=/^\d{4}-\d{2}$/.test(String(d.period||''))?d.period:null;if(!period)return res.status(422).json({error:'A valid report period is required'}); const ids=await chwIdsForUser(req.user); let chwId=req.user.role==='chw'?(ids?.[0]||''):String(d.chw_id||'');if(ids!==null&&!ids.includes(chwId))return res.status(422).json({error:'Choose a CHW in your assigned scope'}); if(!chwId)return res.status(422).json({error:'A linked CHW profile is required'});const id=`RPT-${new Date().toISOString().slice(2,19).replace(/[-:T]/g,'')}-${randomBytes(2).toString('hex')}`;try{await pool.query(`INSERT INTO reports (id,chw_id,period,status,households_visited,household_followups,health_education_sessions,referrals,referral_followups,maternal_activities,child_activities,community_events,other_activities) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,[id,chwId,period,'DRAFT',...['households_visited','household_followups','health_education_sessions','referrals','referral_followups','maternal_activities','child_activities','community_events','other_activities'].map(k=>Math.max(0,Number(d[k]||0)))]);await audit(req.user.id,'CREATE','reports',id,'Created monthly report');res.status(201).json({data:{id}});}catch(e){res.status(422).json({error:e.code==='ER_DUP_ENTRY'?'A report already exists for this CHW and period':e.message});}});
app.patch('/api/reports/:id', auth, requireCsrf, async(req,res)=>{ if(!can(req.user,'report.submit')&&!can(req.user,'report.review'))return res.status(403).json({error:'Forbidden'});const [rows]=await pool.query('SELECT chw_id,status FROM reports WHERE id=?',[req.params.id]);const report=rows[0];if(!report)return res.status(404).json({error:'Report not found'});const ids=await chwIdsForUser(req.user);if(ids!==null&&!ids.includes(String(report.chw_id)))return res.status(404).json({error:'Report not found in your assigned scope'});const status=req.body.status;if(status==='SUBMITTED'){if(!can(req.user,'report.submit'))return res.status(403).json({error:'Forbidden'});if(report.status!=='DRAFT')return res.status(422).json({error:'Only draft reports can be submitted'});await pool.query('UPDATE reports SET status="SUBMITTED",submitted_at=NOW() WHERE id=?',[req.params.id]);await audit(req.user.id,'SUBMIT','reports',req.params.id,'Report submitted for review');return res.json({message:'Report submitted'});}if(!can(req.user,'report.review'))return res.status(403).json({error:'Forbidden'});if(!['UNDER_REVIEW','APPROVED','REJECTED','CORRECTION_REQUIRED'].includes(status))return res.status(422).json({error:'Invalid report status'});await pool.query('UPDATE reports SET status=?,supervisor_comment=?,reviewed_by=?,reviewed_at=NOW() WHERE id=?',[status,req.body.supervisor_comment||null,req.user.id,req.params.id]);await audit(req.user.id,'REVIEW','reports',req.params.id,`Report status changed to ${status}`);res.json({message:'Report updated'});});

app.post('/api/import', auth, requireCsrf, async(req,res)=>{if(!can(req.user,'import.use'))return res.status(403).json({error:'Forbidden'});const dataset=req.body.dataset,records=req.body.records;if(!Array.isArray(records)||records.length<1||records.length>500)return res.status(422).json({error:'Choose a JSON array containing 1 to 500 records.'});const allowed=['chws','households','visits','referrals','education-sessions','community-events'];if(!allowed.includes(dataset))return res.status(422).json({error:'Unsupported dataset'});const cfg=resources[dataset];const perm=writePermissions[dataset];if(!can(req.user,perm))return res.status(403).json({error:'Forbidden'});const conn=await pool.getConnection();let inserted=0,updated=0;try{await conn.beginTransaction();for(const raw of records){let b=await constrainBody(dataset,mapIn(dataset,sanitizeFields(dataset,raw)),req.user);b.id=normalizeCreateId(dataset,b);const keys=Object.keys(b).filter(k=>!protectedColumns.has(k));const [existing]=await conn.query(`SELECT id FROM \`${cfg.table}\` WHERE id=?`,[b.id]);const vals=keys.map(k=>b[k]);const updates=keys.filter(k=>k!=='id').map(k=>`\`${k}\`=VALUES(\`${k}\`)`);await conn.query(`INSERT INTO \`${cfg.table}\` (${keys.map(k=>`\`${k}\``).join(',')}) VALUES (${keys.map(()=>'?').join(',')}) ON DUPLICATE KEY UPDATE ${updates.length?updates.join(','):'id=id'}`,vals);existing.length?updated++:inserted++;}await conn.commit();}catch(e){await conn.rollback();return res.status(422).json({error:'Import failed because one or more records violate database constraints.'});}finally{conn.release();}await audit(req.user.id,'IMPORT',cfg.table,null,`Imported ${inserted} new and updated ${updated} records`);res.json({inserted,updated,total:records.length});});

app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Server error'});});
app.listen(Number(process.env.PORT||5000),()=>console.log(`Rwanda CHW Node API listening on http://localhost:${process.env.PORT||5000}`));
