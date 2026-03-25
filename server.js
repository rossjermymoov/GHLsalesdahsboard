const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── Config (from environment variables) ──
const PORT = process.env.PORT || 3456;
const GHL_API_KEY = process.env.GHL_API_KEY || '';
const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change-me-' + crypto.randomBytes(4).toString('hex');
const GHL_BASE = 'services.leadconnectorhq.com';

// ── Invite code store (persisted to JSON file) ──
const INVITES_FILE = path.join(__dirname, 'invites.json');
let invites = {}; // { code: { createdAt, createdBy, label, active } }
let sessions = {}; // { sessionToken: { code, createdAt } }

function loadInvites() {
  try {
    if (fs.existsSync(INVITES_FILE)) {
      invites = JSON.parse(fs.readFileSync(INVITES_FILE, 'utf8'));
    }
  } catch (e) { invites = {}; }
}
function saveInvites() {
  fs.writeFileSync(INVITES_FILE, JSON.stringify(invites, null, 2));
}
loadInvites();

function generateCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase(); // e.g. "A3F1B2"
}
function generateSession() {
  return crypto.randomBytes(24).toString('hex');
}

// ── Parse helpers ──
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k] = v;
  });
  return cookies;
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  const token = cookies['ghl_session'];
  if (!token || !sessions[token]) return false;
  // Sessions last 7 days
  const s = sessions[token];
  if (Date.now() - s.createdAt > 7 * 24 * 60 * 60 * 1000) {
    delete sessions[token];
    return false;
  }
  return true;
}

function isAdmin(req) {
  const cookies = parseCookies(req);
  return cookies['ghl_admin'] === ADMIN_SECRET;
}

function jsonResponse(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── Server ──
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  // ── CORS preflight ──
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Version, Content-Type',
    });
    res.end();
    return;
  }

  // ── Auth endpoints ──

  // POST /auth/login — validate invite code, set session cookie
  if (url === '/auth/login' && req.method === 'POST') {
    const body = await parseBody(req);
    const code = (body.code || '').trim().toUpperCase();
    if (invites[code] && invites[code].active) {
      const token = generateSession();
      sessions[token] = { code, createdAt: Date.now() };
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'ghl_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800'
      });
      res.end(JSON.stringify({ ok: true }));
    } else {
      jsonResponse(res, 401, { error: 'Invalid or expired invite code.' });
    }
    return;
  }

  // POST /auth/admin — admin login with secret
  if (url === '/auth/admin' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.secret === ADMIN_SECRET) {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'ghl_admin=' + ADMIN_SECRET + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800'
      });
      res.end(JSON.stringify({ ok: true }));
    } else {
      jsonResponse(res, 401, { error: 'Wrong admin secret.' });
    }
    return;
  }

  // GET /auth/check — check if user is logged in
  if (url === '/auth/check') {
    jsonResponse(res, 200, {
      authenticated: isAuthenticated(req),
      isAdmin: isAdmin(req),
      hasCredentials: !!(GHL_API_KEY && GHL_LOCATION_ID)
    });
    return;
  }

  // POST /auth/logout
  if (url === '/auth/logout' && req.method === 'POST') {
    const cookies = parseCookies(req);
    if (cookies['ghl_session']) delete sessions[cookies['ghl_session']];
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'ghl_session=; Path=/; Max-Age=0'
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── Admin endpoints (require admin auth) ──

  // GET /admin/invites — list all invite codes
  if (url === '/admin/invites' && req.method === 'GET') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    jsonResponse(res, 200, { invites });
    return;
  }

  // POST /admin/invites — create new invite code
  if (url === '/admin/invites' && req.method === 'POST') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const body = await parseBody(req);
    const code = generateCode();
    invites[code] = {
      createdAt: Date.now(),
      label: body.label || '',
      active: true
    };
    saveInvites();
    jsonResponse(res, 200, { code, invite: invites[code] });
    return;
  }

  // POST /admin/invites/revoke — revoke an invite code
  if (url === '/admin/invites/revoke' && req.method === 'POST') {
    if (!isAdmin(req)) return jsonResponse(res, 401, { error: 'Unauthorized' });
    const body = await parseBody(req);
    if (invites[body.code]) {
      invites[body.code].active = false;
      saveInvites();
      // Also kill any sessions using this code
      Object.keys(sessions).forEach(t => {
        if (sessions[t].code === body.code) delete sessions[t];
      });
    }
    jsonResponse(res, 200, { ok: true });
    return;
  }

  // ── GHL API proxy (requires auth) ──
  if (req.url.startsWith('/api/')) {
    if (!isAuthenticated(req) && !isAdmin(req)) {
      return jsonResponse(res, 401, { error: 'Not authenticated' });
    }
    // Inject location_id from server config
    let ghlPath = req.url.replace('/api', '');
    if (GHL_LOCATION_ID) {
      const sep = ghlPath.includes('?') ? '&' : '?';
      // Add both param names GHL uses
      if (!ghlPath.includes('location_id') && !ghlPath.includes('locationId')) {
        ghlPath += sep + 'location_id=' + encodeURIComponent(GHL_LOCATION_ID) + '&locationId=' + encodeURIComponent(GHL_LOCATION_ID);
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
      res.writeHead(proxyRes.statusCode, {
        'Content-Type': proxyRes.headers['content-type'] || 'application/json',
      });
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (e) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Proxy error: ' + e.message }));
    });

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      req.pipe(proxyReq);
    } else {
      proxyReq.end();
    }
    return;
  }

  // ── Serve static files ──
  // Login page, admin page, and dashboard are all in index.html (SPA)
  let filePath = url === '/' || url === '/admin' ? '/index.html' : url;
  filePath = path.join(__dirname, filePath);

  const ext = path.extname(filePath);
  const mimeTypes = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };
  const contentType = mimeTypes[ext] || 'text/plain';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ✅ GHL Sales Dashboard running at:');
  console.log('');
  console.log('     http://localhost:' + PORT);
  console.log('');
  if (!GHL_API_KEY || !GHL_LOCATION_ID) {
    console.log('  ⚠️  Set GHL_API_KEY and GHL_LOCATION_ID environment variables');
    console.log('     for server-side API credentials (required for shared access).');
    console.log('');
  }
  console.log('  🔑 Admin secret: ' + ADMIN_SECRET);
  console.log('     Use this to log into /admin and generate invite codes.');
  console.log('');
});
