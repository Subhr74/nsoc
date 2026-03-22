let chart;

async function loadDashboard() {
    const res = await fetch('/api/logs');
    const logs = await res.json();
    const table = document.getElementById('log-body');
    const alerts = document.getElementById('alerts');
    
    table.innerHTML = '';
    alerts.innerHTML = '';

    logs.forEach(log => {
        table.innerHTML += `
            <tr class="${log.status}">
                <td>${log.timestamp}</td>
                <td>${log.ip_address}</td>
                <td><code>${log.payload}</code></td>
                <td>${log.threat_type}</td>
                <td class="${log.severity}">${log.severity}</td>
                <td><button onclick="blockLog(${log.id})">Block</button></td>
            </tr>
        `;
        if (log.severity === 'High' && log.status === 'Active') {
            alerts.innerHTML += `<p style="color:#ef4444">⚠️ HIGH THREAT: ${log.threat_type} from ${log.ip_address}</p>`;
        }
    });

    const statRes = await fetch('/api/stats');
    const stats = await statRes.json();
    updateChart(stats);
}

function updateChart(s) {
    const ctx = document.getElementById('threatChart').getContext('2d');
    if (chart) chart.destroy();
    chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['SQLi', 'XSS', 'Normal'],
            datasets: [{ label: 'Attack Counts', data: [s.sqli, s.xss, s.normal], backgroundColor: ['#ef4444', '#fbbf24', '#22c55e'] }]
        },
        options: { scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } }
    });
}

async function blockLog(id) {
    await fetch(`/api/block/${id}`, { method: 'POST' });
    loadDashboard();
}
async function sendSimulated(type) {
    const randomIP = `192.168.1.${Math.floor(Math.random() * 254)}`;
    let payload = "";

    if (type === 'SQLi') {
        const payloads = ["' OR '1'='1", "admin' --", "SELECT * FROM users", "UNION SELECT NULL, username"];
        payload = payloads[Math.floor(Math.random() * payloads.length)];
    } else if (type === 'XSS') {
        const payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert('XSS')"];
        payload = payloads[Math.floor(Math.random() * payloads.length)];
    } else {
        const payloads = ["GET /index.html", "POST /login", "GET /api/user/profile", "GET /images/logo.png"];
        payload = payloads[Math.floor(Math.random() * payloads.length)];
    }

    await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: randomIP, payload: payload })
    });

    // Refresh dashboard immediately after simulating
    loadDashboard();
}

setInterval(loadDashboard, 3000);
loadDashboard();