import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';
const secret = process.env.JWT_SECRET || 'change-this-development-secret';
export const verifyPassword = (p,h) => bcrypt.compare(p,h);
export const signUser = u => jwt.sign({sub:u.id,role:u.role,email:u.email,type:'access'},secret,{expiresIn:process.env.JWT_EXPIRES_IN||'8h'});
export const signCsrf = userId => jwt.sign({sub:userId,type:'csrf'},secret,{expiresIn:process.env.CSRF_EXPIRES_IN||'8h'});
export const verifyCsrf = (token,userId) => { try { const p=jwt.verify(token,secret); return p.type==='csrf' && String(p.sub)===String(userId); } catch { return false; } };
export async function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Authentication required'});const p=jwt.verify(h.slice(7),secret);if(p.type!=='access')return res.status(401).json({error:'Invalid token'});const [rows]=await pool.query("SELECT * FROM users WHERE id=? AND status='active' LIMIT 1",[p.sub]);if(!rows[0])return res.status(401).json({error:'User inactive or not found'});req.user=rows[0];next();}catch{return res.status(401).json({error:'Invalid or expired token'})}}
export const allow=(...roles)=>(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:'Insufficient permissions'});
