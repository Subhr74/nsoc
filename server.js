/**
 * Advanced Security Operations Center (SOC) Monitoring System
 * server.js — Main backend server
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const geoip = require('geoip-lite');
const path = require('path');

// ─── App Setup ───────────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'soc-super-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 3600000 } // 1 hour
}));

// ─── SQLite Database ──────────────────────────────────────────────────────────
const db = new sqlite3.Database('./soc_logs.db', (err) => {
  if (err) {
    console.error('[DB] Connection error:', err.message);
  } else {
    console.log('[DB] Connected to SQLite database.');
  }
});

// Create logs table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    country    TEXT DEFAULT 'Unknown',
    latitude   REAL DEFAULT 0,
    longitude  REAL DEFAULT 0,
    payload    TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity   TEXT NOT NULL,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) console.error('[DB] Table creation error:', err.message);
  else console.log('[DB] Logs table ready.');
});

// ─── Threat Detection Engine ──────────────────────────────────────────────────
const THREAT_PATTERNS = [
  {
    type: 'SQL Injection',
    severity: 'HIGH',
    patterns: [
      /('|%27)\s*(or|OR)\s*('|%27)?\s*\d+\s*=\s*\d+/i,
      /union\s+select/i,
      /--\s*$/,
      /;\s*(drop|delete|insert|update)\s+/i,
      /' OR '1'='1/i,
      /SLEEP\s*\(\d+\)/i,
      /BENCHMARK\s*\(/i,
      /xp_cmdshell/i
    ]
  },
  {
    type: 'XSS',
    severity: 'MEDIUM',
    patterns: [
      /<script[\s>]/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /javascript\s*:/i,
      /<iframe/i,
      /document\.cookie/i,
      /eval\s*\(/i,
      /alert\s*\(/i
    ]
  },
  {
    type: 'Path Traversal',
    severity: 'CRITICAL',
    patterns: [
      /\.\.\//,
      /\.\.%2f/i,
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /\/windows\/system32/i,
      /%252e%252e/i
    ]
  },
  {
    type: 'RCE',
    severity: 'CRITICAL',
    patterns: [
      /\bbash\b/i,
      /cmd\.exe/i,
      /powershell/i,
      /\bwget\s+http/i,
      /\bcurl\s+http/i,
      /\/bin\/sh/i,
      /nc\s+-e/i,
      /system\s*\(/i,
      /exec\s*\(/i
    ]
  }
];

/**
 * Analyzes a payload string for threats.
 * Returns { threat_type, severity } or null if benign.
 */
function detectThreat(payload) {
  for (const threat of THREAT_PATTERNS) {
    for (const pattern of threat.patterns) {
      if (pattern.test(payload)) {
        return { threat_type: threat.type, severity: threat.severity };
      }
    }
  }
  return { threat_type: 'Normal Traffic', severity: 'INFO' };
}

/**
 * Geolocates an IP address.
 * Falls back to random world coordinates for private/unknown IPs.
 */
function geolocateIP(ip) {
  // Strip IPv6 prefix if present
  const cleanIP = ip.replace(/^::ffff:/, '');

  const geo = geoip.lookup(cleanIP);
  if (geo && geo.ll) {
    return {
      country: geo.country || 'Unknown',
      latitude: geo.ll[0],
      longitude: geo.ll[1]
    };
  }

  // For private/loopback IPs, simulate random global locations
  const locations = [
    { country: 'US', latitude: 37.7749, longitude: -122.4194 },
    { country: 'RU', latitude: 55.7558, longitude: 37.6173 },
    { country: 'CN', latitude: 39.9042, longitude: 116.4074 },
    { country: 'DE', latitude: 52.5200, longitude: 13.4050 },
    { country: 'BR', latitude: -23.5505, longitude: -46.6333 },
    { country: 'IN', latitude: 28.6139, longitude: 77.2090 },
    { country: 'KP', latitude: 39.0392, longitude: 125.7625 },
    { country: 'IR', latitude: 35.6892, longitude: 51.3890 },
    { country: 'NG', latitude: 9.0820,  longitude: 8.6753 },
    { country: 'UA', latitude: 50.4501, longitude: 30.5234 }
  ];
  return locations[Math.floor(Math.random() * locations.length)];
}

/**
 * Saves a log entry to the DB and broadcasts it via Socket.io.
 */
function saveAndBroadcast(ip, payload) {
  const { threat_type, severity } = detectThreat(payload);
  const geo = geolocateIP(ip);

  const stmt = db.prepare(`
    INSERT INTO logs (ip, country, latitude, longitude, payload, threat_type, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    ip,
    geo.country,
    geo.latitude,
    geo.longitude,
    payload,
    threat_type,
    severity,
    function (err) {
      if (err) {
        console.error('[DB] Insert error:', err.message);
        return;
      }
      const logEntry = {
        id: this.lastID,
        ip,
        country: geo.country,
        latitude: geo.latitude,
        longitude: geo.longitude,
        payload,
        threat_type,
        severity,
        timestamp: new Date().toISOString()
      };
      // Broadcast to all connected Socket.io clients
      io.emit('new_log', logEntry);
      console.log(`[LOG] [${severity}] ${threat_type} from ${ip} (${geo.country})`);
    }
  );

  stmt.finalize();
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.redirect('/');
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Serve login page
app.get('/', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.redirect('/dashboard.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'password123') {
    req.session.authenticated = true;
    req.session.user = username;
    return res.redirect('/dashboard.html');
  }
  res.redirect('/?error=1');
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Protect dashboard
app.get('/dashboard.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// REST: Get all logs (paginated, latest first)
app.get('/api/logs', requireAuth, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  db.all(
    'SELECT * FROM logs ORDER BY id DESC LIMIT ?',
    [limit],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// REST: Log stats summary
app.get('/api/stats', requireAuth, (req, res) => {
  db.all(`
    SELECT threat_type, severity, COUNT(*) as count
    FROM logs
    GROUP BY threat_type, severity
    ORDER BY count DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// REST: Simulate / ingest an attack payload
app.post('/api/simulate', requireAuth, (req, res) => {
  const { payload, ip } = req.body;
  if (!payload) return res.status(400).json({ error: 'payload required' });

  // Use provided IP or extract from request
  const sourceIP = ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '8.8.8.8';
  saveAndBroadcast(sourceIP, payload);
  res.json({ status: 'ok', message: 'Payload analysed and logged.' });
});

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`[WS] Client connected: ${socket.id}`);

  // Send last 50 logs on connect so the dashboard isn't empty
  db.all('SELECT * FROM logs ORDER BY id DESC LIMIT 50', [], (err, rows) => {
    if (!err) {
      socket.emit('history', rows.reverse());
    }
  });

  socket.on('disconnect', () => {
    console.log(`[WS] Client disconnected: ${socket.id}`);
  });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║   SOC Monitoring System — ONLINE         ║`);
  console.log(`║   http://localhost:${PORT}                   ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
});