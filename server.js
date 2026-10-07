import express from 'express';
import http from 'http';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import pg from 'pg';
import { Server } from 'socket.io';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://messenger:messenger@localhost:5432/messenger';
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const MAX_FILE_SIZE = 25 * 1024 * 1024;
const MAX_AVATAR_SIZE = 5 * 1024 * 1024;

if (JWT_SECRET === 'dev-only-change-me' && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET must be set in production');
}

const uploadsDir = path.join(__dirname, 'uploads');
const avatarsDir = path.join(uploadsDir, 'avatars');
const filesDir = path.join(uploadsDir, 'files');
fs.mkdirSync(avatarsDir, { recursive: true });
fs.mkdirSync(filesDir, { recursive: true });

const pool = new Pool({ connectionString: DATABASE_URL, max: 20, idleTimeoutMillis: 30000 });
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true }, maxHttpBufferSize: 2e6 });

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '1mb' }));
app.get('/health', (_req,res)=>res.json({ok:true, time:now()}));
app.use('/uploads', express.static(uploadsDir, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 80, standardHeaders: 'draft-8', legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 240, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/api', apiLimiter);
app.use(['/api/register', '/api/login'], authLimiter);

const publicUser = row => ({
  id: Number(row.id),
  username: row.username,
  avatar_url: row.avatar_url ? `${PUBLIC_URL}${row.avatar_url}` : null,
  online: onlineUsers.has(Number(row.id)),
  last_seen: row.last_seen
});

function sign(user) {
  return jwt.sign({ id: Number(user.id), username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}

function getToken(req) {
  const header = req.headers.authorization || '';
  return header.replace(/^Bearer\s+/i, '').trim();
}

async function auth(req, res, next) {
  try {
    const token = getToken(req);
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Недействительная сессия' });
  }
}

async function isMember(conversationId, userId) {
  const { rows } = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [conversationId, userId]);
  return rows.length > 0;
}

async function getConversation(id, viewerId) {
  const { rows } = await pool.query(`
    SELECT c.id, c.type, c.name, c.owner_id, c.created_at,
      COALESCE((SELECT m2.text FROM messages m2 WHERE m2.conversation_id=c.id ORDER BY m2.id DESC LIMIT 1), '') AS last_text,
      (SELECT m3.created_at FROM messages m3 WHERE m3.conversation_id=c.id ORDER BY m3.id DESC LIMIT 1) AS last_at,
      cm.unread_count
    FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_id=$2
    WHERE c.id=$1`, [id, viewerId]);
  if (!rows[0]) return null;
  const c = rows[0];
  const members = await pool.query(`
    SELECT u.id,u.username,u.avatar_url,u.last_seen
    FROM users u JOIN conversation_members cm ON cm.user_id=u.id
    WHERE cm.conversation_id=$1 ORDER BY u.username`, [id]);
  const result = {
    id: Number(c.id), type: c.type, name: c.name, owner_id: c.owner_id ? Number(c.owner_id) : null,
    created_at: c.created_at, last_text: c.last_text || null, last_at: c.last_at, unread_count: Number(c.unread_count || 0),
    members: members.rows.map(publicUser)
  };
  if (c.type === 'direct') {
    result.other_user = result.members.find(u => u.id !== Number(viewerId)) || null;
    result.title = result.other_user?.username || 'Чат';
  } else result.title = c.name || 'Группа';
  return result;
}

async function getConversations(userId) {
  const { rows } = await pool.query(`
    SELECT c.id FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id
    WHERE cm.user_id=$1 ORDER BY c.id DESC`, [userId]);
  const list = [];
  for (const row of rows) {
    const item = await getConversation(row.id, userId);
    if (item) list.push(item);
  }
  return list.sort((a,b) => (b.last_at || b.created_at).toString().localeCompare((a.last_at || a.created_at).toString()));
}

async function emitConversationUpdate(conversationId) {
  const members = await pool.query('SELECT user_id FROM conversation_members WHERE conversation_id=$1', [conversationId]);
  for (const row of members.rows) {
    const summary = await getConversation(conversationId, row.user_id);
    if (summary) io.to(`user:${row.user_id}`).emit('conversation:update', summary);
  }
}

function now() { return new Date().toISOString(); }
function cleanFilename(name) { return path.basename(name).replace(/[^\p{L}\p{N}._ -]/gu, '_').slice(0, 120) || 'file'; }

const fileStorage = multer.diskStorage({
  destination: (_req, file, cb) => cb(null, filesDir),
  filename: (_req, file, cb) => cb(null, `${crypto.randomUUID()}-${cleanFilename(file.originalname)}`)
});
const avatarStorage = multer.diskStorage({
  destination: (_req, file, cb) => cb(null, avatarsDir),
  filename: (_req, file, cb) => cb(null, `${crypto.randomUUID()}${path.extname(cleanFilename(file.originalname)).toLowerCase()}`)
});
const allowedFile = (req, file, cb) => {
  if (!file.mimetype || !['image/', 'application/pdf', 'text/', 'application/zip', 'application/json', 'application/octet-stream'].some(x => file.mimetype.startsWith(x))) return cb(new Error('Этот тип файла не поддерживается'));
  cb(null, true);
};
const uploadFile = multer({ storage: fileStorage, limits: { fileSize: MAX_FILE_SIZE }, fileFilter: allowedFile });
const uploadAvatar = multer({ storage: avatarStorage, limits: { fileSize: MAX_AVATAR_SIZE }, fileFilter: (_r, f, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/i.test(f.mimetype)) });

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const publicKey = typeof req.body.publicKey === 'object' ? req.body.publicKey : null;
  const privateKeyBox = typeof req.body.privateKeyBox === 'object' ? req.body.privateKeyBox : null;
  if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) return res.status(400).json({ error: 'Имя: 3–24 символа, только буквы, цифры, _ или -' });
  if (password.length < 8) return res.status(400).json({ error: 'Пароль должен быть не короче 8 символов' });
  try {
    const hash = await bcrypt.hash(password, 12);
    if (!publicKey || !privateKeyBox?.salt || !privateKeyBox?.iv || !privateKeyBox?.ciphertext) return res.status(400).json({ error: 'Не удалось создать ключ шифрования' });
    const { rows } = await pool.query('INSERT INTO users(username,password_hash,public_key,private_key_box,created_at,last_seen) VALUES($1,$2,$3,$4,NOW(),NOW()) RETURNING id,username,avatar_url,last_seen', [username, hash, JSON.stringify(publicKey), JSON.stringify(privateKeyBox)]);
    const user = rows[0];
    res.json({ token: sign(user), user: publicUser(user) });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Такое имя уже занято' });
    console.error(e); res.status(500).json({ error: 'Не удалось создать аккаунт' });
  }
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT id,username,password_hash,public_key,private_key_box,avatar_url,last_seen FROM users WHERE LOWER(username)=LOWER($1)', [username]);
  const row = rows[0];
  if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
  await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [row.id]);
  res.json({ token: sign(row), user: publicUser(row), crypto: { publicKey: row.public_key ? JSON.parse(row.public_key) : null, privateKeyBox: row.private_key_box ? JSON.parse(row.private_key_box) : null } });
});

app.get('/api/me', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id,username,avatar_url,last_seen FROM users WHERE id=$1', [req.user.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ user: publicUser(rows[0]) });
});

app.post('/api/me/avatar', auth, uploadAvatar.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Выберите изображение' });
  const url = `/uploads/avatars/${req.file.filename}`;
  const old = await pool.query('SELECT avatar_url FROM users WHERE id=$1', [req.user.id]);
  await pool.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [url, req.user.id]);
  if (old.rows[0]?.avatar_url) try { fs.unlinkSync(path.join(__dirname, old.rows[0].avatar_url.replace(/^\//, ''))); } catch {}
  const { rows } = await pool.query('SELECT id,username,avatar_url,last_seen FROM users WHERE id=$1', [req.user.id]);
  io.to(`user:${req.user.id}`).emit('me:update', publicUser(rows[0]));
  res.json({ user: publicUser(rows[0]) });
});

app.get('/api/users', auth, async (req, res) => {
  const q = String(req.query.q || '').trim();
  const { rows } = await pool.query(`SELECT id,username,avatar_url,last_seen FROM users WHERE id<>$1 AND username ILIKE $2 ORDER BY username LIMIT 30`, [req.user.id, `%${q}%`]);
  res.json({ users: rows.map(publicUser) });
});


app.get('/api/me/crypto', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT public_key,private_key_box FROM users WHERE id=$1',[req.user.id]);
  if (!rows[0]) return res.status(404).json({error:'Пользователь не найден'});
  res.json({publicKey: rows[0].public_key ? JSON.parse(rows[0].public_key) : null, privateKeyBox: rows[0].private_key_box ? JSON.parse(rows[0].private_key_box) : null});
});

app.post('/api/me/crypto', auth, async (req, res) => {
  const publicKey = String(req.body.publicKey || '').trim();
  if (!publicKey || publicKey.length > 10000) return res.status(400).json({ error: 'Некорректный открытый ключ' });
  await pool.query('UPDATE users SET public_key=$1 WHERE id=$2', [publicKey, req.user.id]);
  res.json({ ok: true });
});

app.get('/api/users/:id/crypto', auth, async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query('SELECT id,username,public_key FROM users WHERE id=$1', [id]);
  if (!rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ id:Number(rows[0].id), username:rows[0].username, publicKey:rows[0].public_key });
});

app.get('/api/conversations/:id/keys', auth, async (req, res) => {
  const id = Number(req.params.id);
  if (!(await isMember(id, req.user.id))) return res.status(403).json({ error: 'Нет доступа к этому чату' });
  const { rows } = await pool.query('SELECT user_id,encrypted_key FROM conversation_keys WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]);
  res.json({ encryptedKey: rows[0]?.encrypted_key || null });
});

async function setConversationKeys(client, conversationId, envelopes) {
  for (const e of envelopes) {
    await client.query(`INSERT INTO conversation_keys(conversation_id,user_id,encrypted_key) VALUES($1,$2,$3) ON CONFLICT(conversation_id,user_id) DO UPDATE SET encrypted_key=EXCLUDED.encrypted_key`, [conversationId, e.userId, e.encryptedKey]);
  }
}

app.post('/api/conversations/:id/keys', auth, async (req, res) => {
  const id = Number(req.params.id);
  if (!(await isMember(id, req.user.id))) return res.status(403).json({ error: 'Нет доступа к этому чату' });
  const envelopes = Array.isArray(req.body.envelopes) ? req.body.envelopes : [];
  const members = await pool.query('SELECT user_id FROM conversation_members WHERE conversation_id=$1', [id]);
  const allowed = new Set(members.rows.map(x=>Number(x.user_id)));
  if (!envelopes.length || envelopes.some(x=>!allowed.has(Number(x.userId)) || typeof x.encryptedKey !== 'string')) return res.status(400).json({ error: 'Некорректные ключи' });
  for (const e of envelopes) if (String(e.encryptedKey).length > 10000) return res.status(400).json({ error: 'Слишком большой ключ' });
  const client=await pool.connect(); try { await client.query('BEGIN'); await setConversationKeys(client,id,envelopes.map(e=>({userId:Number(e.userId),encryptedKey:e.encryptedKey}))); await client.query('COMMIT'); } catch(e){await client.query('ROLLBACK');throw e;} finally{client.release();}
  res.json({ok:true});
});

app.get('/api/conversations', auth, async (req, res) => res.json({ conversations: await getConversations(req.user.id) }));

app.post('/api/conversations/direct', auth, async (req, res) => {
  const otherId = Number(req.body.userId);
  if (!otherId || otherId === req.user.id) return res.status(400).json({ error: 'Выберите другого пользователя' });
  const other = await pool.query('SELECT id FROM users WHERE id=$1', [otherId]);
  if (!other.rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  const existing = await pool.query(`
    SELECT c.id FROM conversations c
    WHERE c.type='direct' AND (SELECT COUNT(*) FROM conversation_members cm WHERE cm.conversation_id=c.id)=2
      AND EXISTS(SELECT 1 FROM conversation_members x WHERE x.conversation_id=c.id AND x.user_id=$1)
      AND EXISTS(SELECT 1 FROM conversation_members y WHERE y.conversation_id=c.id AND y.user_id=$2) LIMIT 1`, [req.user.id, otherId]);
  if (existing.rows[0]) return res.json({ conversation: await getConversation(existing.rows[0].id, req.user.id) });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const c = await client.query("INSERT INTO conversations(type,created_at) VALUES('direct',NOW()) RETURNING id");
    const id = c.rows[0].id;
    await client.query('INSERT INTO conversation_members(conversation_id,user_id,unread_count,joined_at) VALUES($1,$2,0,NOW()),($1,$3,0,NOW())', [id, req.user.id, otherId]);
    await client.query('COMMIT');
    const summary = await getConversation(id, req.user.id);
    io.to(`user:${otherId}`).emit('conversation:new', await getConversation(id, otherId));
    io.to(`user:${req.user.id}`).emit('conversation:new', summary);
    res.json({ conversation: summary });
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
});

app.post('/api/conversations/group', auth, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const ids = [...new Set((Array.isArray(req.body.userIds) ? req.body.userIds : []).map(Number).filter(Boolean))].filter(id => id !== req.user.id);
  if (!name) return res.status(400).json({ error: 'Введите название группы' });
  if (!ids.length) return res.status(400).json({ error: 'Добавьте хотя бы одного участника' });
  const valid = await pool.query('SELECT id FROM users WHERE id=ANY($1::int[])', [ids]);
  if (!valid.rows.length) return res.status(400).json({ error: 'Выберите существующих участников' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const c = await client.query("INSERT INTO conversations(type,name,owner_id,created_at) VALUES('group',$1,$2,NOW()) RETURNING id", [name, req.user.id]);
    const id = c.rows[0].id;
    const members = [req.user.id, ...valid.rows.map(x => Number(x.id))];
    for (const userId of members) await client.query('INSERT INTO conversation_members(conversation_id,user_id,unread_count,joined_at) VALUES($1,$2,0,NOW())', [id, userId]);
    await client.query('COMMIT');
    for (const userId of members) io.to(`user:${userId}`).emit('conversation:new', await getConversation(id, userId));
    res.json({ conversation: await getConversation(id, req.user.id) });
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
});

app.get('/api/conversations/:id/messages', auth, async (req, res) => {
  const id = Number(req.params.id);
  if (!(await isMember(id, req.user.id))) return res.status(403).json({ error: 'Нет доступа к этому чату' });
  const { rows } = await pool.query(`
    SELECT m.id,m.conversation_id,m.sender_id,m.ciphertext,m.iv,m.file_iv,m.created_at,m.attachment_url,m.attachment_name,m.attachment_mime,m.attachment_size,u.username AS sender_username,u.avatar_url AS sender_avatar
    FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=$1 ORDER BY m.id DESC LIMIT 200`, [id]);
  res.json({ messages: rows.reverse().map(x => ({ ...x, id:Number(x.id), conversation_id:Number(x.conversation_id), sender_id:Number(x.sender_id), attachment_url:x.attachment_url ? `${PUBLIC_URL}${x.attachment_url}` : null })) });
});

app.post('/api/conversations/:id/read', auth, async (req, res) => {
  const id = Number(req.params.id);
  if (!(await isMember(id, req.user.id))) return res.status(403).json({ error: 'Нет доступа к этому чату' });
  await pool.query('UPDATE conversation_members SET unread_count=0,last_read_at=NOW() WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]);
  io.to(`user:${req.user.id}`).emit('conversation:read', { conversationId: id });
  res.json({ ok: true });
});

app.post('/api/conversations/:id/messages', auth, uploadFile.single('file'), async (req, res) => {
  const id = Number(req.params.id);
  if (!(await isMember(id, req.user.id))) return res.status(403).json({ error: 'Нет доступа к этому чату' });
  const ciphertext = String(req.body.ciphertext || '');
  const iv = String(req.body.iv || '');
  const fileIv = req.file ? String(req.body.fileIv || '') : null;
  if (!ciphertext || !iv || !/^[A-Za-z0-9_-]+$/.test(ciphertext) || !/^[A-Za-z0-9_-]+$/.test(iv) || (req.file && (!fileIv || !/^[A-Za-z0-9_-]+$/.test(fileIv)))) return res.status(400).json({ error: 'Сообщение должно быть зашифровано на устройстве' });
  const attachmentUrl = req.file ? `/uploads/files/${req.file.filename}` : null;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const m = await client.query(`INSERT INTO messages(conversation_id,sender_id,ciphertext,iv,file_iv,text,created_at,attachment_url,attachment_name,attachment_mime,attachment_size)
      VALUES($1,$2,$3,$4,$5,NULL,NOW(),$6,$7,$8,$9)
      RETURNING id,conversation_id,sender_id,text,created_at,attachment_url,attachment_name,attachment_mime,attachment_size`, [id, req.user.id, ciphertext, iv, fileIv, attachmentUrl, req.file?.originalname || null, req.file?.mimetype || null, req.file?.size || null]);
    await client.query('UPDATE conversation_members SET unread_count=unread_count+1 WHERE conversation_id=$1 AND user_id<>$2', [id, req.user.id]);
    await client.query('UPDATE conversation_members SET last_read_at=NOW(), unread_count=0 WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]);
    await client.query('COMMIT');
    const row = m.rows[0];
    const payload = { ...row, id:Number(row.id), conversation_id:Number(row.conversation_id), sender_id:Number(row.sender_id), sender_username:req.user.username, sender_avatar:null, attachment_url:row.attachment_url ? `${PUBLIC_URL}${row.attachment_url}` : null };
    const members = await pool.query('SELECT user_id FROM conversation_members WHERE conversation_id=$1', [id]);
    for (const member of members.rows) io.to(`user:${member.user_id}`).emit('message:new', { conversationId:id, message:payload });
    await emitConversationUpdate(id);
    res.json({ message: payload });
  } catch (e) {
    await client.query('ROLLBACK');
    if (req.file) try { fs.unlinkSync(path.join(filesDir, req.file.filename)); } catch {}
    throw e;
  } finally { client.release(); }
});

const onlineUsers = new Map();
const userSockets = new Map();
function addOnline(userId, socketId) {
  const set = userSockets.get(userId) || new Set(); set.add(socketId); userSockets.set(userId, set); onlineUsers.set(userId, true);
}
async function removeOnline(userId, socketId) {
  const set = userSockets.get(userId); if (!set) return;
  set.delete(socketId);
  if (!set.size) {
    userSockets.delete(userId); onlineUsers.delete(userId);
    await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [userId]);
    io.emit('presence:update', { userId, online:false, last_seen:now() });
  }
}

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth?.token, JWT_SECRET);
    next();
  } catch { next(new Error('Unauthorized')); }
});
io.on('connection', async socket => {
  const userId = Number(socket.user.id);
  addOnline(userId, socket.id);
  socket.join(`user:${userId}`);
  io.emit('presence:update', { userId, online:true, last_seen:null });
  socket.on('disconnect', () => removeOnline(userId, socket.id).catch(console.error));
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Файл слишком большой' : err.message });
  if (err) { console.error(err); return res.status(400).json({ error: err.message || 'Ошибка' }); }
  res.status(500).json({ error:'Ошибка сервера' });
});

app.get('*splat', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(24) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      public_key TEXT,
      private_key_box TEXT,
      avatar_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS private_key_box TEXT;
    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      type VARCHAR(10) NOT NULL CHECK(type IN ('direct','group')),
      name VARCHAR(60), owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      unread_count INTEGER NOT NULL DEFAULT 0,
      last_read_at TIMESTAMPTZ,
      PRIMARY KEY(conversation_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS conversation_keys (
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_key TEXT NOT NULL,
      PRIMARY KEY(conversation_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ciphertext TEXT NOT NULL DEFAULT '',
      iv TEXT NOT NULL DEFAULT '',
      file_iv TEXT,
      text TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      attachment_url TEXT,
      attachment_name TEXT,
      attachment_mime TEXT,
      attachment_size BIGINT
    );
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS ciphertext TEXT NOT NULL DEFAULT '';
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS iv TEXT NOT NULL DEFAULT '';
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_iv TEXT;
    CREATE INDEX IF NOT EXISTS messages_conversation_id_id_idx ON messages(conversation_id,id DESC);
    CREATE INDEX IF NOT EXISTS conversation_members_user_id_idx ON conversation_members(user_id);
  `);
}

await migrate();
server.listen(PORT, () => console.log(`Pink Messenger running on ${PUBLIC_URL}`));
