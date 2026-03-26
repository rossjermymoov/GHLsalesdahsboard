const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── Config ──
const PORT = process.env.PORT || 3456;
const GHL_API_KEY = process.env.GHL_API_KEY || '';
const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change-me-' + crypto.randomBytes(4).toString('hex');
const GHL_BASE = 'services.leadconnectorhq.com';

// ── Data stores (persisted to JSON) ──
// DATA_DIR should point to a persistent volume on Railway (e.g. /data)
// Falls back to app directory for local development
const DATA_DIR = process.env.DATA_DIR || __dirname;
if (!fs.existsSync(DATA_DIR)) { fs.mkdirSync(DATA_DIR, { recursive: true }); }
const INVITES_FILE = path.join(DATA_DIR, 'invites.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const METRICS_FILE = path.join(DATA_DIR, 'weekly-metrics.json');

let invites = {};   // { code: { name, createdAt, active, usedBy } }
let users = {};      // { email: { name, passwordHash, salt, inviteCode, createdAt, active } }
let sessions = {};   // { token: { email, createdAt, isAdmin } }
let weeklyMetrics = {}; // { "2026-W13": { talkTimeHrs, talkTimeMins, totalCalls, clientsLive, clientsLost, referrals } }

function loadData() {
  try { if (fs.existsSync(INVITES_FILE)) invites = JSON.parse(fs.readFileSync(INVITES_FILE, 'utf8')); } catch (e) { invites = {}; }
  try { if (fs.existsSync(USERS_FILE)) users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { users = {}; }
  try { if (fs.existsSync(METRICS_FILE)) weeklyMetrics = JSON.parse(fs.readFileSync(METRICS_FILE, 'utf8')); } catch (e) { weeklyMetrics = {}; }
}
function saveMetrics() { fs.writeFileSync(METRICS_FILE, JSON.stringify(weeklyMetrics, null, 2)); }
function saveInvites() { fs.writeFileSync(INVITES_FILE, JSON.stringify(invites, null, 2)); }
function saveUsers() { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
loadData();

// ── Password hashing (scrypt — built into Node, no dependencies) ──
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      resolve({ hash: key.toString('hex'), salt });
    });
  });
}

function verifyPassword(password, hash, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      resolve(key.toString('hex') === hash);
    });
  });
}

function getCurrentWeek() {
  const now = new Date();
  const jan1 = new Date(now.getFullYear(), 0, 1);
  const days = Math.floor((now - jan1) / 86400000);
  const weekNum = Math.ceil((days + jan1.getDay() + 1) / 7);
  return now.getFullYear() + '-W' + String(weekNum).padStart(2, '0');
}

function generateCode() { return crypto.randomBytes(3).toString('hex').toUpperCase(); }
function generateSession() { return crypto.randomBytes(24).toString('hex'); }

// ── Helpers ──
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const parts = c.trim().split('=');
    if (parts[0]) cookies[parts[0]] = parts.slice(1).join('=');
  });
  return cookies;
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies['ghl_session'];
  if (!token || !sessions[token]) return null;
  const s = sessions[token];
  if (Date.now() - s.createdAt > 7 * 24 * 60 * 60 * 1000) { delete sessions[token]; return null; }
  return s;
}

function isAuthenticated(req) { return !!getSession(req); }

function isAdmin(req) {
  const s = getSession(req);
  return s && s.isAdmin;
}

function jsonResponse(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function setCookie(res, name, value, maxAge) {
  return name + '=' + value + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + maxAge;
}

// ── Server ──
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Version, Content-Type',
    });
    res.end();
    return;
  }

  // ════════════════════════════════════════
  // AUTH ENDPOINTS
  // ════════════════════════════════════════

  // POST /auth/validate-invite — check if invite code is valid (step 1 of registration)
  if (url === '/auth/validate-invite' && req.method === 'POST') {
    const body = await parseBody(req);
    const code = (body.code || '').trim().toUpperCase();
    if (invites[code] && invites[code].active) {
      jsonResponse(res, 200, { ok: true, name: invites[code].name || '' });
    } else {
      jsonResponse(res, 401, { error: 'Invalid or expired invite code.' });
    }
    return;
  }

  // POST /auth/register — create account with invite code + email + password (step 2)
  if (url === '/auth/register' && req.method === 'POST') {
    const body = await parseBody(req);
    const code = (body.code || '').trim().toUpperCase();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';
    const name = (body.name || '').trim();

    if (!invites[code] || !invites[code].active) {
      return jsonResponse(res, 401, { error: 'Invalid or expired invite code.' });
    }
    if (!email || !email.includes('@')) {
      return jsonResponse(res, 400, { error: 'Please enter a valid email address.' });
    }
    if (password.length < 6) {
      return jsonResponse(res, 400, { error: 'Password must be at least 6 characters.' });
    }
    if (users[email]) {
      return jsonResponse(res, 400, { error: 'An account with this email already exists. Try logging in instead.' });
    }

    const { hash, salt } = await hashPassword(password);
    users[email] = {
      name: name || invites[code].name || email.split('@')[0],
      passwordHash: hash,
      salt: salt,
      inviteCode: code,
      createdAt: Date.now(),
      active: true
    };
    saveUsers();

    // Mark invite as used
    invites[code].usedBy = email;
    invites[code].active = false;
    saveInvites();

    // Auto-login after registration
    const token = generateSession();
    sessions[token] = { email, createdAt: Date.now(), isAdmin: false };
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': setCookie(res, 'ghl_session', token, 604800)
    });
    res.end(JSON.stringify({ ok: true, name: users[email].name }));
    return;
  }

  // POST /auth/login — login with email + password
  if (url === '/auth/login' && req.method === 'POST') {
    const body = await parseBody(req);
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    const user = users[email];
    if (!user || !user.active) {
      return jsonResponse(res, 401, { error: 'Invalid email or password.' });
    }

    const valid = await verifyPassword(password, user.passwordHash, user.salt);
    if (!valid) {
      return jsonResponse(res, 401, { error: 'Invalid email or password.' });
    }

    const token = generateSession();
    sessions[token] = { email, createdAt: Date.now(), isAdmin: false };
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': setCookie(res, 'ghl_session', token, 604800)
    });
    res.end(JSON.stringify({ ok: true, name: user.name }));
    return;
  }

  // POST /auth/admin — admin login
  if (url === '/auth/admin' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.secret === ADMIN_SECRET) {
      const token = generateSession();
      sessions[token] = { email: 'admin', createdAt: Date.now(), isAdmin: true };
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': setCookie(res, 'ghl_session', token, 604800)
      });
      res.end(JSON.stringify({ ok: true }));
    } else {
      jsonResponse(res, 401, { error: 'Wrong admin secret.' });
    }
    return;
  }

  // GET /auth/check
  if (url === '/auth/check') {
    const s = getSession(req);
    const userName = s && !s.isAdmin && users[s.email] ? users[s.email].name : '';
    jsonResponse(res, 200, {
      authenticated: !!s,
      isAdmin: s ? s.isAdmin : false,
      name: userName,
      hasCredentials: !!(GHL_API_KEY && GHL_LOCATION_ID)
    });
    return;
  }

  // POST /auth/logout
  if (url === '/auth/logout' && req.method === 'POST') {
    const cookies = parseCookies(req);
    const token = cookies['ghl_session'];
    if (token) delete sessions[token];
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'ghl_session=; Path=/; Max-Age=0'
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ════════════════════════════════════════
  // ADMIN ENDPOINTS
  // ════════════════════════════════════════

  // GET /admin/invites
  if (url === '/admin/invites' && req.method === 'GET') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    jsonResponse(res, 200, { invites });
    return;
  }

  // POST /admin/invites — create invite (with name for the person)
  if (url === '/admin/invites' && req.method === 'POST') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const body = await parseBody(req);
    const code = generateCode();
    invites[code] = {
      name: body.name || '',
      createdAt: Date.now(),
      active: true,
      usedBy: null
    };
    saveInvites();
    jsonResponse(res, 200, { code, invite: invites[code] });
    return;
  }

  // POST /admin/invites/revoke
  if (url === '/admin/invites/revoke' && req.method === 'POST') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const body = await parseBody(req);
    if (invites[body.code]) {
      invites[body.code].active = false;
      saveInvites();
    }
    jsonResponse(res, 200, { ok: true });
    return;
  }

  // GET /admin/users — list all registered users
  if (url === '/admin/users' && req.method === 'GET') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const safeUsers = {};
    Object.entries(users).forEach(([email, u]) => {
      safeUsers[email] = { name: u.name, createdAt: u.createdAt, active: u.active, inviteCode: u.inviteCode };
    });
    jsonResponse(res, 200, { users: safeUsers });
    return;
  }

  // POST /admin/users/deactivate — disable a user account
  if (url === '/admin/users/deactivate' && req.method === 'POST') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const body = await parseBody(req);
    if (users[body.email]) {
      users[body.email].active = false;
      saveUsers();
      // Kill their sessions
      Object.keys(sessions).forEach(t => { if (sessions[t].email === body.email) delete sessions[t]; });
    }
    jsonResponse(res, 200, { ok: true });
    return;
  }

  // POST /admin/users/activate — re-enable a user account
  if (url === '/admin/users/activate' && req.method === 'POST') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const body = await parseBody(req);
    if (users[body.email]) { users[body.email].active = true; saveUsers(); }
    jsonResponse(res, 200, { ok: true });
    return;
  }

  // ════════════════════════════════════════
  // WEEKLY METRICS ENDPOINTS
  // ════════════════════════════════════════

  // GET /metrics/weekly?week=2026-W13  (returns metrics for that week, or current week if omitted)
  if (url === '/metrics/weekly' && req.method === 'GET') {
    if (!isAuthenticated(req)) return jsonResponse(res, 401, { error: 'Not authenticated' });
    const params = new URL(req.url, 'http://localhost').searchParams;
    const week = params.get('week') || getCurrentWeek();
    jsonResponse(res, 200, { week, metrics: weeklyMetrics[week] || {} });
    return;
  }

  // POST /metrics/weekly — save manual metrics for a week
  if (url === '/metrics/weekly' && req.method === 'POST') {
    if (!isAuthenticated(req)) return jsonResponse(res, 401, { error: 'Not authenticated' });
    const body = await parseBody(req);
    const week = body.week || getCurrentWeek();
    weeklyMetrics[week] = Object.assign(weeklyMetrics[week] || {}, body.metrics || {});
    saveMetrics();
    jsonResponse(res, 200, { ok: true, week, metrics: weeklyMetrics[week] });
    return;
  }

  // ════════════════════════════════════════
  // GHL API PROXY
  // ════════════════════════════════════════
  if (req.url.startsWith('/api/')) {
    if (!isAuthenticated(req)) {
      return jsonResponse(res, 401, { error: 'Not authenticated' });
    }
    let ghlPath = req.url.replace('/api', '');
    if (GHL_LOCATION_ID) {
      const sep = ghlPath.includes('?') ? '&' : '?';
      // GHL API is inconsistent: /opportunities/search uses location_id (snake_case)
      // while /opportunities/pipelines uses locationId (camelCase)
      const pathOnly = ghlPath.split('?')[0];
      if (pathOnly.includes('/search')) {
        // Search endpoints use snake_case
        if (!ghlPath.includes('location_id')) {
          ghlPath += sep + 'location_id=' + encodeURIComponent(GHL_LOCATION_ID);
        }
      } else {
        // Other endpoints use camelCase
        if (!ghlPath.includes('locationId')) {
          ghlPath += sep + 'locationId=' + encodeURIComponent(GHL_LOCATION_ID);
        }
      }
    }
    const options = {
      hostname: GHL_BASE,
      path: ghlPath,
      method: req.method,
      headers: {
        'Authorization': 'Bearer ' + GHL_API_KEY,
        'Version': '2021-07-28',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      }
    };

    const proxyReq = https.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, { 'Content-Type': proxyRes.headers['content-type'] || 'application/json' });
      proxyRes.pipe(res);
    });
    proxyReq.on('error', (e) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Proxy error: ' + e.message }));
    });
    if (req.method !== 'GET' && req.method !== 'HEAD') { req.pipe(proxyReq); } else { proxyReq.end(); }
    return;
  }

  // ════════════════════════════════════════
  // STATIC FILES
  // ════════════════════════════════════════
  let filePath = url === '/' || url === '/admin' ? '/index.html' : url;
  filePath = path.join(__dirname, filePath);
  const ext = path.extname(filePath);
  const mimeTypes = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  GHL Sales Dashboard running at:');
  console.log('     http://localhost:' + PORT);
  console.log('');
  if (!GHL_API_KEY || !GHL_LOCATION_ID) {
    console.log('  Set GHL_API_KEY and GHL_LOCATION_ID environment variables.');
    console.log('');
  }
  console.log('  Admin secret: ' + ADMIN_SECRET);
  console.log('');
});
