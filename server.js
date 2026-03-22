const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./soc_data.db');


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'soc-secret-node',
    resave: false,
    saveUninitialized: true
}));

// Create Database Table
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        payload TEXT,
        threat_type TEXT,
        severity TEXT,
        status TEXT DEFAULT 'Active'
    )`);
    
    // Insert dummy data if empty
    db.get("SELECT COUNT(*) as count FROM logs", (err, row) => {
        if (row.count === 0) {
            db.run("INSERT INTO logs (ip_address, payload, threat_type, severity) VALUES ('192.168.1.1', 'GET /login', 'Normal', 'Low')");
            db.run("INSERT INTO logs (ip_address, payload, threat_type, severity) VALUES ('45.1.2.3', 'OR 1=1 --', 'SQL Injection', 'High')");
        }
    });
});

// Threat Detection Logic
function detectThreat(payload) {
    const p = payload.toUpperCase();
    if (p.includes("SELECT") || p.includes("UNION") || p.includes("OR 1=1")) return { type: "SQL Injection", sev: "High" };
    if (p.includes("<SCRIPT>") || p.includes("ALERT(")) return { type: "XSS", sev: "Medium" };
    return { type: "Normal", sev: "Low" };
}

// Routes
app.post('/login', (req, res) => {
    if (req.body.username === 'admin' && req.body.password === 'password123') {
        req.session.loggedIn = true;
        res.redirect('/dashboard.html');
    } else {
        res.send("Invalid credentials. <a href='/'>Go back</a>");
    }
});

app.get('/api/logs', (req, res) => {
    db.all("SELECT * FROM logs ORDER BY id DESC LIMIT 50", (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/stats', (req, res) => {
    const query = `SELECT 
        SUM(case when threat_type = 'SQL Injection' then 1 else 0 end) as sqli,
        SUM(case when threat_type = 'XSS' then 1 else 0 end) as xss,
        SUM(case when threat_type = 'Normal' then 1 else 0 end) as normal
        FROM logs`;
    db.get(query, (err, row) => res.json(row));
});

app.post('/api/block/:id', (req, res) => {
    db.run("UPDATE logs SET status = 'Blocked' WHERE id = ?", [req.params.id], () => {
        res.json({ success: true });
    });
});
// Endpoint to receive simulated traffic
app.post('/api/simulate', express.json(), (req, res) => {
    const { payload, ip } = req.body;
    
    // Use our detection logic
    const detection = detectThreat(payload);
    
    const query = `INSERT INTO logs (ip_address, payload, threat_type, severity) 
                   VALUES (?, ?, ?, ?)`;
    
    db.run(query, [ip, payload, detection.type, detection.sev], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});
app.listen(3000, () => console.log('SOC Server running at http://localhost:3000'));