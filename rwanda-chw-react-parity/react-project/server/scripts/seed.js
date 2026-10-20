import fs from 'node:fs';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import { pool } from '../src/db.js';

const dir = path.resolve(process.cwd(), '../rwanda-chw-react/public/data');
const files = {
  provinces:'provinces', districts:'districts', sectors:'sectors', cells:'cells', villages:'villages', facilities:'facilities',
  chws:'chws', households:'households', visits:'visits', referrals:'referrals', education_sessions:'education-sessions',
  community_events:'community-events', reports:'reports', notifications:'notifications', audit_logs:'audit-logs'
};
const transform = {
  visits:r=>({ ...r, visit_date:r.date, date:undefined }),
  referrals:r=>({ ...r, referral_date:r.referral_date||r.date, date:undefined }),
  education_sessions:r=>({ ...r, session_date:r.date, date:undefined }),
  community_events:r=>({ ...r, event_date:r.date, date:undefined }),
  notifications:r=>({ ...r, read_flag:r.read?1:0, read:undefined, type:undefined }),
};
function rows(name){const p=path.join(dir,`${files[name]}.json`);return JSON.parse(fs.readFileSync(p,'utf8')).map(r=>transform[name]?.(r)||r);}
async function insert(conn,table,data){for(const raw of data){const row=Object.fromEntries(Object.entries(raw).filter(([,v])=>v!==undefined));const keys=Object.keys(row);await conn.query(`INSERT INTO \`${table}\` (${keys.map(k=>`\`${k}\``).join(',')}) VALUES (${keys.map(()=>'?').join(',')}) ON DUPLICATE KEY UPDATE ${keys.filter(k=>k!=='id').map(k=>`\`${k}\`=VALUES(\`${k}\`)`).join(',')||'id=id'}` ,keys.map(k=>row[k]));}}
try{
 const conn=await pool.getConnection(); await conn.beginTransaction();
 await conn.query('SET FOREIGN_KEY_CHECKS=0');
 for(const n of ['provinces','districts','sectors','cells','villages','facilities']) await insert(conn,n,rows(n));
 const users=JSON.parse(fs.readFileSync(path.join(dir,'users.json'),'utf8'));
 for(const u of users){await conn.query(`INSERT INTO users (id,email,name,role,province_id,district_id,sector_id,facility_id,status,password_hash) VALUES (?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE email=VALUES(email),name=VALUES(name),role=VALUES(role),province_id=VALUES(province_id),district_id=VALUES(district_id),sector_id=VALUES(sector_id),facility_id=VALUES(facility_id),status=VALUES(status),password_hash=VALUES(password_hash)`,[u.id,u.email.toLowerCase(),u.name,u.role,u.province_id,u.district_id,u.sector_id,u.facility_id,u.status,await bcrypt.hash(u.password,12)]);}
 for(const n of ['chws','households','visits','referrals','education_sessions','community_events','reports','notifications']) await insert(conn,n,rows(n));
 await conn.query('SET FOREIGN_KEY_CHECKS=1'); await conn.commit(); conn.release(); console.log('MySQL seed complete. Demo password: Demo@123');
}catch(e){console.error(e);process.exitCode=1;}finally{await pool.end();}
