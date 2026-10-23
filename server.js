'use strict';
/**
 * SmartEXAM LAN host — binds 0.0.0.0 so other devices on the school network can open the app.
 * Admin:  http://<this-pc-ip>:<port>/admin-by-e-c-1771
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { URL } = require('url');

const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const PORT = Number(process.env.PORT || process.env.SE_PORT || 1771);
const HOST = process.env.SE_HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2'
};

function ensureDir(d) { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); }
ensureDir(DATA);

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8');
}

const secretsPath = path.join(DATA, 'secrets.json');
if (!fs.existsSync(secretsPath)) {
  writeJson(secretsPath, {
    adminPassword: '',
    groqKey1: '',
    groqKey2: '',
    firebaseApiKey: '',
    firebaseDb: '',
    reportEmail: '',
    graderEmail: '',
    graderPassword: ''
  });
}

const FILES = {
  secrets: secretsPath,
  sessions: path.join(DATA, 'sessions.json'),
  teachers: path.join(DATA, 'teachers.json'),
  ai: path.join(DATA, 'ai-state.json'),
  chat: path.join(DATA, 'ai-chat.json'),
  sim: path.join(DATA, 'sim-workspace.json'),
  reports: path.join(DATA, 'ai-reports.json')
};

// Нууц утгыг эхлээд орчны хувьсагчаас (Render/Railway), байхгүй бол data/secrets.json-оос уншина
function secrets() {
  const f = readJson(FILES.secrets, {});
  const e = process.env;
  const o = {
    adminPassword: e.ADMIN_PASSWORD, groqKey1: e.GROQ_KEY_1, groqKey2: e.GROQ_KEY_2,
    firebaseApiKey: e.FIREBASE_API_KEY, firebaseDb: e.FIREBASE_DB, reportEmail: e.REPORT_EMAIL,
    graderEmail: e.GRADER_EMAIL, graderPassword: e.GRADER_PASSWORD
  };
  Object.keys(o).forEach((k) => { if (o[k]) f[k] = o[k]; });
  return f;
}
function sessions() { return readJson(FILES.sessions, {}); }
function teachers() { return readJson(FILES.teachers, []); }
function aiState() {
  return readJson(FILES.ai, {
    enabled: false,
    start: '08:00',
    end: '18:00',
    extraEmail: '',
    simLogin: '',
    simUid: '',
    lastTick: 0,
    lastReportAt: 0,
    commands: []
  });
}
function chatLog() { return readJson(FILES.chat, []); }
function simWs() {
  return readJson(FILES.sim, { exams: [], assignments: [], studentWork: [], audits: [] });
}

const tokens = sessions();
const loginFails = {};

function lanIps() {
  const out = [];
  const ifs = os.networkInterfaces();
  Object.keys(ifs).forEach((name) => {
    (ifs[name] || []).forEach((i) => {
      if (i.family === 'IPv4' && !i.internal) out.push(i.address);
    });
  });
  return out;
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > 2e6) { req.destroy(); reject(new Error('too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { resolve({ _raw: raw }); }
    });
    req.on('error', reject);
  });
}

function httpsJson(method, urlStr, headers, bodyObj) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const body = bodyObj == null ? null : JSON.stringify(bodyObj);
    const opts = {
      method,
      hostname: u.hostname,
      path: u.pathname + u.search,
      headers: Object.assign({
        'Content-Type': 'application/json',
        Accept: 'application/json'
      }, headers || {})
    };
    if (body) opts.headers['Content-Length'] = Buffer.byteLength(body);
    const req = https.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = JSON.parse(text); } catch { parsed = { _text: text }; }
        resolve({ status: res.statusCode, data: parsed, text });
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

function teacherEmail(login) {
  const s = String(login || '').trim().toLowerCase();
  if (!s) return '';
  if (s.includes('@')) return s;
  const safe = s.replace(/[^a-z0-9._-]/g, '');
  return safe + '@smartexam.app';
}

function authAdmin(req) {
  const h = String(req.headers.authorization || '');
  const tok = h.replace(/^Bearer\s+/i, '').trim();
  if (!tok) return false;
  const rec = tokens[tok];
  if (!rec) return false;
  if (Date.now() - rec.at > 12 * 3600 * 1000) { delete tokens[tok]; writeJson(FILES.sessions, tokens); return false; }
  rec.at = Date.now();
  return true;
}

function pushChat(role, text, extra) {
  const list = chatLog();
  list.push(Object.assign({
    id: crypto.randomBytes(6).toString('hex'),
    t: new Date().toISOString(),
    role,
    text: String(text || '').slice(0, 4000)
  }, extra || {}));
  while (list.length > 400) list.shift();
  writeJson(FILES.chat, list);
  return list[list.length - 1];
}

function inSchedule(st) {
  const now = new Date();
  const hm = now.getHours() * 60 + now.getMinutes();
  const [sh, sm] = String(st.start || '00:00').split(':').map(Number);
  const [eh, em] = String(st.end || '23:59').split(':').map(Number);
  const a = (sh || 0) * 60 + (sm || 0);
  const b = (eh || 23) * 60 + (em || 59);
  if (a <= b) return hm >= a && hm <= b;
  return hm >= a || hm <= b;
}

async function groqChat(which, messages, maxTok) {
  const s = secrets();
  const key = which === 2 ? s.groqKey2 : s.groqKey1;
  if (!key) throw new Error('GROQ key missing');
  const r = await httpsJson('POST', 'https://api.groq.com/openai/v1/chat/completions', {
    Authorization: 'Bearer ' + key
  }, {
    model: 'llama-3.1-8b-instant',
    temperature: 0.3,
    max_tokens: maxTok || 280,
    messages
  });
  if (r.status >= 400) throw new Error((r.data && r.data.error && r.data.error.message) || ('Groq ' + r.status));
  const msg = r.data && r.data.choices && r.data.choices[0] && r.data.choices[0].message;
  return (msg && msg.content) || '';
}

async function sendReportEmail(toList, subject, message) {
  const s = secrets();
  const addrs = Array.from(new Set([s.reportEmail, ...toList].filter(Boolean)));
  const results = [];
  for (const to of addrs) {
    try {
      const r = await httpsJson('POST', 'https://formsubmit.co/ajax/' + encodeURIComponent(to), {
        Accept: 'application/json'
      }, {
        name: 'SmartEXAM AI',
        _subject: subject,
        message
      });
      results.push({ to, ok: r.status < 400, status: r.status });
    } catch (e) {
      results.push({ to, ok: false, error: e.message });
    }
  }
  const reports = readJson(FILES.reports, []);
  reports.push({ t: new Date().toISOString(), subject, message: message.slice(0, 8000), results });
  writeJson(FILES.reports, reports.slice(-80));
  return results;
}

function compactLogs(n) {
  return chatLog().slice(-n).map((m) => m.role + ': ' + String(m.text).replace(/\s+/g, ' ').slice(0, 180)).join('\n');
}

async function workerTick() {
  const st = aiState();
  if (!st.enabled || !inSchedule(st)) return;
  const now = Date.now();
  if (now - (st.lastTick || 0) < 40000) return; // rate limit
  st.lastTick = now;
  writeJson(FILES.ai, st);

  const ws = simWs();
  const sys = 'MN school exam sim. Reply compact MN/EN. Max 80 words. No secrets.';
  const cmd = (st.commands || []).shift();
  if (cmd) writeJson(FILES.ai, st);

  try {
    // AI4 first if admin queued a command
    if (cmd) {
      const out = await groqChat(2, [
        { role: 'system', content: sys + ' You are AI4 admin secretary. Do the task or report AI1-3 status.' },
        { role: 'user', content: ('CMD:' + cmd + '\nLOG:\n' + compactLogs(8)).slice(0, 1200) }
      ], 220);
      pushChat('AI4', out, { kind: 'command' });
    }

    const exams = ws.exams || [];
    const lastExam = exams[exams.length - 1];

    const a1 = await groqChat(1, [
      { role: 'system', content: sys + ' You are AI1 Teacher. Output JSON only: {"title":"","q":[{"t":"","type":"mcq|blank|match|open","opts":[],"ans":""}]} 2-3 questions, English grade 11 style.' },
      { role: 'user', content: 'Make a tiny practice set. Topic rotate: vocab match / gerund / so that.' }
    ], 320);
    pushChat('AI1', a1, { kind: 'teach' });
    let exam = null;
    try {
      const m = a1.match(/\{[\s\S]*\}/);
      exam = m ? JSON.parse(m[0]) : { title: 'AI дасгал', q: [] };
    } catch { exam = { title: 'AI дасгал', raw: a1.slice(0, 400) }; }
    exam.id = 'sim-' + Date.now();
    exam.at = new Date().toISOString();
    exam.owner = st.simLogin || 'sim';
    ws.exams = (ws.exams || []).slice(-20).concat([exam]);

    const a2 = await groqChat(1, [
      { role: 'system', content: sys + ' You are AI2 Student. Answer the quiz briefly as JSON {"answers":[]}' },
      { role: 'user', content: JSON.stringify(exam).slice(0, 900) }
    ], 200);
    pushChat('AI2', a2, { kind: 'student' });
    ws.studentWork = (ws.studentWork || []).slice(-20).concat([{ examId: exam.id, a2, at: exam.at }]);

    const a3 = await groqChat(2, [
      { role: 'system', content: sys + ' You are AI3 auditor. Find bugs/unclear text. JSON {"bugs":[],"ideas":[]}' },
      { role: 'user', content: ('AI1:\n' + a1 + '\nAI2:\n' + a2 + '\nLOG:\n' + compactLogs(6)).slice(0, 1400) }
    ], 240);
    pushChat('AI3', a3, { kind: 'audit' });
    ws.audits = (ws.audits || []).slice(-20).concat([{ at: exam.at, a3 }]);
    writeJson(FILES.sim, ws);
  } catch (e) {
    pushChat('SYS', 'AI алдаа: ' + (e.message || e), { kind: 'error' });
  }

  // End-of-window report once
  const st2 = aiState();
  const [eh, em] = String(st2.end || '18:00').split(':').map(Number);
  const nowD = new Date();
  const endMin = (eh || 18) * 60 + (em || 0);
  const hm = nowD.getHours() * 60 + nowD.getMinutes();
  const dayKey = nowD.toISOString().slice(0, 10);
  if (hm >= endMin && st2.lastReportAt !== dayKey && (ws.exams || []).length) {
    const body = 'SmartEXAM AI өдрийн тайлан ' + dayKey + '\n\n' + compactLogs(30);
    try {
      await sendReportEmail([st2.extraEmail], 'SmartEXAM AI тайлан ' + dayKey, body);
      pushChat('SYS', 'Тайлан имэйл илгээлээ.', { kind: 'mail' });
    } catch (e) {
      pushChat('SYS', 'Имэйл алдаа: ' + e.message, { kind: 'error' });
    }
    st2.lastReportAt = dayKey;
    writeJson(FILES.ai, st2);
  }
}

setInterval(() => { workerTick().catch((e) => console.warn('tick', e.message)); }, 15000);

// ================= Серверт дүгнэх (answerKeys хөтөч рүү огт гарахгүй) =================
const SAFE_KEY = /^[^.#$\[\]\/\s]{1,100}$/;
let graderCache = { token: '', uid: '', exp: 0 };

async function graderAuth() {
  if (graderCache.token && Date.now() < graderCache.exp) return graderCache;
  const s = secrets();
  if (!s.graderEmail || !s.graderPassword) throw new Error('GRADER_EMAIL / GRADER_PASSWORD тохируулаагүй');
  const r = await httpsJson('POST',
    'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=' + encodeURIComponent(s.firebaseApiKey),
    {}, { email: s.graderEmail, password: s.graderPassword, returnSecureToken: true });
  if (r.status !== 200 || !r.data || !r.data.idToken) throw new Error('grader нэвтэрч чадсангүй');
  graderCache = {
    token: r.data.idToken,
    uid: r.data.localId,
    exp: Date.now() + Math.max(60, Number(r.data.expiresIn || 3600) - 300) * 1000
  };
  return graderCache;
}

async function fbDb(method, p, body) {
  const s = secrets();
  const g = await graderAuth();
  const base = String(s.firebaseDb || '').replace(/\/$/, '');
  const r = await httpsJson(method, base + '/' + p + '.json?auth=' + encodeURIComponent(g.token), {}, body);
  if (r.status === 401 || r.status === 403) graderCache.exp = 0;
  if (r.status < 200 || r.status >= 300) throw new Error('db ' + method + ' ' + r.status);
  return r.data;
}

async function verifyIdToken(idToken) {
  if (!idToken || typeof idToken !== 'string' || idToken.length > 4000) return null;
  const s = secrets();
  const r = await httpsJson('POST',
    'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(s.firebaseApiKey),
    {}, { idToken });
  const u = r.status === 200 && r.data && r.data.users && r.data.users[0];
  if (!u || u.disabled) return null;
  return { uid: u.localId, name: u.displayName || '', anon: !(u.providerUserInfo && u.providerUserInfo.length) };
}

const normBlankSrv = (v) => String(v == null ? '' : v).toLowerCase().replace(/[\s.,;:!?"'«»()\-–—_]+/g, ' ').trim();
function answersEqualSrv(got, expected, type) {
  if (expected == null || expected === '') return false;
  if (type === 'blank') {
    const gb = normBlankSrv(got);
    return gb.length > 0 && String(expected).split('|').map(normBlankSrv).filter(Boolean).indexOf(gb) >= 0;
  }
  const g = String(got == null ? '' : got).trim().toUpperCase();
  const e = String(expected).trim().toUpperCase();
  if (type === 'grid') {
    const nz = (v) => String(v == null ? '' : v).replace(/\D/g, '').replace(/^0+(?=\d)/, '');
    const gn = nz(got), en = nz(expected);
    return gn.length > 0 && en.length > 0 && gn === en;
  }
  return g === e;
}

async function handleGrade(req, res) {
  try {
    const b = await readBody(req);
    const roomId = String(b.roomId || '');
    if (!SAFE_KEY.test(roomId)) return json(res, 400, { error: 'roomId буруу' });
    const user = await verifyIdToken(b.idToken);
    if (!user) return json(res, 401, { error: 'Нэвтрэлт баталгаажсангүй' });

    const ans = (b.answers && typeof b.answers === 'object') ? b.answers : {};
    if (JSON.stringify(ans).length > 200000) return json(res, 413, { error: 'Хариулт хэт том' });

    const allKeys = await fbDb('GET', 'activeRooms/' + roomId + '/answerKeys');
    if (!allKeys) return json(res, 404, { error: 'Answer key олдсонгүй' });
    const label = String(b.variantLabel || '').slice(0, 20);
    const rawKeys = allKeys[label] || allKeys[Object.keys(allKeys)[0]];
    const keyList = (Array.isArray(rawKeys) ? rawKeys : Object.values(rawKeys || {})).filter(Boolean);
    const subset = Array.isArray(b.subset) ? b.subset : null;

    let correct = 0, total = 0;
    const wrongIds = [];
    keyList.forEach((q) => {
      if (q.answer == null || q.answer === '') return;
      if (subset && subset.indexOf(q.id) < 0) return;
      total++;
      if (answersEqualSrv(ans[q.id], q.answer, q.type)) correct++; else wrongIds.push(q.id);
    });
    if (!total) return json(res, 422, { error: 'Зөв хариултын түлхүүр хоосон байна' });
    const score = Math.round((correct / total) * 100);
    const id = crypto.randomBytes(8).toString('hex');
    const at = new Date().toISOString();
    const name = String(b.studentName || '').slice(0, 80);
    const timeSpentSec = Math.max(0, Math.min(86400, Number(b.timeSpentSec) || 0));

    // Алдсан асуултаа дахин ажиллах үед өрөөний дүнд нэмэхгүй
    if (!subset) {
      await fbDb('PUT', 'activeRooms/' + roomId + '/submissions/' + id, {
        id, uid: user.uid, examId: roomId, answers: ans, score, correctCount: correct, totalCount: total,
        studentName: name, studentClass: String(b.studentClass || '').slice(0, 80),
        variantLabel: label, studentVersion: label,
        cheatLog: Array.isArray(b.cheatLog) ? b.cheatLog.slice(0, 200) : [],
        timeSpentSec, submittedAt: at, verified: true, gradedBy: 'cloud'
      });
    }

    // Ангийн дүн / оролдлогын түүх: оноог СЕРВЕР бичнэ (сурагч өөрөө бичиж чадахгүй)
    const at2 = b.attempt && typeof b.attempt === 'object' ? b.attempt : null;
    if (at2 && !user.anon && SAFE_KEY.test(String(at2.classId || ''))) {
      try {
        const member = await fbDb('GET', 'studentClasses/' + user.uid + '/' + at2.classId);
        if (member === true) {
          const mode = subset ? 'mistakes' : 'full';
          const extra = !!at2.extra;
          const rec = {
            at, score, correct, total, sec: timeSpentSec, mode, variant: label || 'A',
            title: String(at2.title || '').slice(0, 200), kind: at2.kind === 'practice' ? 'practice' : 'exam',
            wrongIds
          };
          if (extra) rec.extra = true;
          await fbDb('PUT', 'attempts/' + user.uid + '/' + roomId + '/' + id, rec);
          await fbDb('PUT', 'classResults/' + at2.classId + '/' + roomId + '/' + user.uid + '/' + id,
            { name: user.name || 'Сурагч', at, score, sec: timeSpentSec, mode, extra });
        }
      } catch (e) { console.warn('attempt save', e.message); }
    }

    return json(res, 200, { id, score, correctCount: correct, totalCount: total, wrongIds });
  } catch (e) {
    console.warn('grade', e.message);
    return json(res, 500, { error: 'Дүгнэх үед алдаа: ' + e.message });
  }
}

async function handleApi(req, res, url) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS'
    });
    res.end();
    return;
  }

  const p = url.pathname;
  if (p === '/api/health') {
    return json(res, 200, { ok: true, ips: lanIps(), port: PORT, time: new Date().toISOString() });
  }

  if (p === '/api/grade' && req.method === 'POST') return handleGrade(req, res);

  if (p === '/api/admin/login' && req.method === 'POST') {
    const body = await readBody(req);
    const s = secrets();
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const lf = loginFails[ip] || { n: 0, until: 0 };
    if (Date.now() < lf.until) return json(res, 429, { ok: false, error: 'Олон удаа буруу оруулсан. 10 минут хүлээнэ үү' });
    const want = String(s.adminPassword || '');
    if (!want || String(body.password || '') !== want) {
      lf.n++;
      if (lf.n >= 5) { lf.until = Date.now() + 10 * 60 * 1000; lf.n = 0; }
      loginFails[ip] = lf;
      return json(res, 401, { ok: false, error: want ? 'Нууц үг буруу' : 'ADMIN_PASSWORD тохируулаагүй байна' });
    }
    delete loginFails[ip];
    const tok = crypto.randomBytes(24).toString('hex');
    tokens[tok] = { at: Date.now() };
    writeJson(FILES.sessions, tokens);
    return json(res, 200, { ok: true, token: tok });
  }

  if (p === '/api/admin/me') {
    if (!authAdmin(req)) return json(res, 401, { ok: false });
    return json(res, 200, { ok: true });
  }

  if (!p.startsWith('/api/admin/')) return json(res, 404, { error: 'not found' });
  if (!authAdmin(req)) return json(res, 401, { ok: false, error: 'admin' });

  if (p === '/api/admin/teachers' && req.method === 'GET') {
    return json(res, 200, { ok: true, teachers: teachers().map((t) => ({ login: t.login, email: t.email, name: t.name, uid: t.uid, createdAt: t.createdAt })) });
  }

  if (p === '/api/admin/teachers' && req.method === 'POST') {
    const body = await readBody(req);
    const login = String(body.login || '').trim();
    const password = String(body.password || '');
    const name = String(body.name || login).trim();
    if (!login || password.length < 6) return json(res, 400, { ok: false, error: 'Нэвтрэх нэр болон 6+ нууц үг хэрэгтэй' });
    const email = teacherEmail(login);
    const s = secrets();
    let uid = '';
    try {
      const r = await httpsJson('POST',
        'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=' + encodeURIComponent(s.firebaseApiKey),
        {},
        { email, password, returnSecureToken: true });
      if (r.status >= 400) {
        const msg = (r.data && r.data.error && r.data.error.message) || JSON.stringify(r.data);
        return json(res, 400, { ok: false, error: msg });
      }
      uid = r.data.localId;
      const idToken = r.data.idToken;
      await httpsJson('POST',
        'https://identitytoolkit.googleapis.com/v1/accounts:update?key=' + encodeURIComponent(s.firebaseApiKey),
        {},
        { idToken, displayName: name, returnSecureToken: false });
      const db = String(s.firebaseDb || '').replace(/\/$/, '');
      const payload = JSON.stringify({ role: 'teacher', name, login, email, createdBy: 'admin' });
      await httpsJson('PUT', db + '/users/' + uid + '.json?auth=' + encodeURIComponent(idToken), {}, JSON.parse(payload));
      await httpsJson('PUT', db + '/teachers/' + uid + '.json?auth=' + encodeURIComponent(idToken), {}, {
        displayName: name, email, login, createdAt: new Date().toISOString()
      });
    } catch (e) {
      return json(res, 500, { ok: false, error: e.message });
    }
    const list = teachers();
    list.push({ login, email, name, uid, createdAt: new Date().toISOString() });
    writeJson(FILES.teachers, list);
    return json(res, 200, { ok: true, email, uid });
  }

  if (p.startsWith('/api/admin/teachers/') && req.method === 'DELETE') {
    const login = decodeURIComponent(p.split('/').pop());
    writeJson(FILES.teachers, teachers().filter((t) => t.login !== login && t.email !== login));
    return json(res, 200, { ok: true });
  }

  if (p === '/api/admin/ai/state' && req.method === 'GET') {
    const st = aiState();
    return json(res, 200, { ok: true, state: st, inSchedule: inSchedule(st), chat: chatLog().slice(-80), sim: simWs() });
  }

  if (p === '/api/admin/ai/state' && req.method === 'POST') {
    const body = await readBody(req);
    const st = aiState();
    if (typeof body.enabled === 'boolean') st.enabled = body.enabled;
    if (body.start) st.start = String(body.start).slice(0, 5);
    if (body.end) st.end = String(body.end).slice(0, 5);
    if (body.extraEmail != null) st.extraEmail = String(body.extraEmail).trim();
    if (body.simLogin != null) st.simLogin = String(body.simLogin).trim();
    writeJson(FILES.ai, st);
    pushChat('SYS', st.enabled ? ('AI асаалаа ' + st.start + '–' + st.end) : 'AI унтраалаа');
    return json(res, 200, { ok: true, state: st });
  }

  if (p === '/api/admin/ai/command' && req.method === 'POST') {
    const body = await readBody(req);
    const text = String(body.text || '').trim();
    if (!text) return json(res, 400, { ok: false, error: 'хоосон' });
    const st = aiState();
    st.commands = st.commands || [];
    st.commands.push(text.slice(0, 500));
    writeJson(FILES.ai, st);
    pushChat('ADMIN', text, { kind: 'inbox' });
    return json(res, 200, { ok: true });
  }

  if (p === '/api/admin/ai/email' && req.method === 'POST') {
    const body = await readBody(req);
    const extra = String(body.to || aiState().extraEmail || '').trim();
    const msg = String(body.message || compactLogs(40));
    const results = await sendReportEmail([extra], String(body.subject || 'SmartEXAM мэдэгдэл'), msg);
    return json(res, 200, { ok: true, results });
  }

  json(res, 404, { error: 'not found' });
}

function isAdminPath(p) {
  return p === '/admin-by-e-c-1771' || p === '/amdin-by-e-c-1771' || p === '/admin-by-e-c-1771/' || p === '/amdin-by-e-c-1771/';
}

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, buf) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-store' : 'public, max-age=120'
    });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
    if (url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
      return;
    }
    let p = decodeURIComponent(url.pathname);
    if (p === '/') p = '/index.html';
    if (isAdminPath(p)) {
      serveFile(res, path.join(ROOT, 'index.html'));
      return;
    }
    const safe = path.normalize(p).replace(/^(\.\.[/\\])+/, '');
    const filePath = path.join(ROOT, safe);
    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403); res.end(); return;
    }
    // Нууц болон серверийн файлуудыг хөтчид ХЭЗЭЭ Ч өгөхгүй (data/secrets.json гэх мэт)
    const rel = path.relative(ROOT, filePath).replace(/\\/g, '/').toLowerCase();
    if (/^(data|node_modules|\.git)(\/|$)/.test(rel) ||
        /(^|\/)\./.test(rel) ||
        /^(server\.js|package(-lock)?\.json|secrets\.json|sessions\.json|ai-[^/]*\.json|_groq[^/]*|[^/]*\.bat)$/.test(rel)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found'); return;
    }
    fs.stat(filePath, (err, st) => {
      if (!err && st.isFile()) return serveFile(res, filePath);
      serveFile(res, path.join(ROOT, 'index.html'));
    });
  } catch (e) {
    json(res, 500, { error: e.message });
  }
});

server.listen(PORT, HOST, () => {
  const ips = lanIps();
  console.log('SmartEXAM LAN host');
  console.log('  Local:  http://127.0.0.1:' + PORT + '/');
  ips.forEach((ip) => console.log('  LAN:    http://' + ip + ':' + PORT + '/'));
  console.log('  Admin:  http://' + (ips[0] || '127.0.0.1') + ':' + PORT + '/admin-by-e-c-1771');
});
