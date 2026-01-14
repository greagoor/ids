const SUPABASE_URL = "https://nqhmyubxbemwhckqzyjm.supabase.co";
const API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5xaG15dWJ4YmVtd2hja3F6eWptIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyNzMyNjcsImV4cCI6MjA4Mjg0OTI2N30.r382XoEZ413P9fjjLBYu4cu9S5ULGcNWFHUctSnTAKo";

let incidents = [];
let alerts = [];
let lastAlertAttackTypes = [];
let attackChart;
let severityChart;


async function loadIncidents() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/active_incidents`,
    {
      headers: {
        "apikey": API_KEY,
        "Authorization": `Bearer ${API_KEY}`
      }
    }
  );

  incidents = await res.json();
  populateAttackTypes();
  applyFilters();
}

function populateAttackTypes() {
  const select = document.getElementById("attackFilter");
  const types = [...new Set(incidents.map(i => i.attack_type))];

  select.innerHTML = `<option value="ALL">ALL</option>`;
  types.forEach(t => {
    select.innerHTML += `<option value="${t}">${t}</option>`;
  });
}

function applyFilters() {
  const severity = document.getElementById("severityFilter").value;
  const attack = document.getElementById("attackFilter").value;
  const ip = document.getElementById("ipFilter").value.trim();

  let filtered = incidents;

  if (severity !== "ALL") {
    filtered = filtered.filter(i => i.incident_severity === severity);
  }

  if (attack !== "ALL") {
    filtered = filtered.filter(i => i.attack_type === attack);
  }

  if (ip) {
    filtered = filtered.filter(i => i.src_ip.includes(ip));
  }

  renderTable(filtered);
}

function renderTable(data) {
  const tbody = document.querySelector("#incidents tbody");
  tbody.innerHTML = "";

  data.forEach(i => {
    const row = `
      <tr>
        <td>${i.attack_type}</td>
        <td>${i.src_ip || "N/A"}</td>
        <td class="sev-${i.incident_severity}">${i.incident_severity}</td>
        <td>${i.alert_count}</td>
        <td>${new Date(i.last_seen).toLocaleString()}</td>
      </tr>
    `;
    tbody.innerHTML += row;
  });
}

/* Hook filters */
document.getElementById("severityFilter").onchange = applyFilters;
document.getElementById("attackFilter").onchange = applyFilters;
document.getElementById("ipFilter").oninput = applyFilters;

loadIncidents();
loadAlerts();

setInterval(() => {
  loadIncidents();
  loadAlerts();
  renderAttackChart();
renderSeverityChart();
}, 5000);

async function loadAlerts() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/alerts_last_24h?limit=100`,
    {
      headers: {
        "apikey": API_KEY,
        "Authorization": `Bearer ${API_KEY}`
      }
    }
  );

  alerts = await res.json();
  populateAlertAttackTypes();
  applyAlertFilters();
}


function renderAlerts(alerts) {
  const tbody = document.querySelector("#alerts tbody");
  tbody.innerHTML = "";

  alerts.forEach(a => {
    const row = `
      <tr>
        <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
        <td>${a.attack_type}</td>
        <td>${a.src_ip || "N/A"}</td>
        <td class="sev-${severityText(a.severity)}">
          ${severityText(a.severity)}
        </td>
        <td>${a.confidence}</td>
        <td>${a.uri}</td>
      </tr>
    `;
    tbody.innerHTML += row;
  });
}

document.getElementById("alertSeverityFilter").onchange = applyAlertFilters;
document.getElementById("alertAttackFilter").onchange = applyAlertFilters;
document.getElementById("alertIpFilter").oninput = applyAlertFilters;

function severityText(sev) {
  if (sev === 4) return "CRITICAL";
  if (sev === 3) return "HIGH";
  if (sev === 2) return "MEDIUM";
  return "LOW";
}
function populateAlertAttackTypes() {
  const types = [...new Set(alerts.map(a => a.attack_type))];

  if (JSON.stringify(types) === JSON.stringify(lastAlertAttackTypes)) {
    return; // 🚀 nothing changed
  }

  lastAlertAttackTypes = types;

  const select = document.getElementById("alertAttackFilter");
  const currentValue = select.value;

  select.innerHTML = `<option value="ALL">ALL</option>`;
  types.forEach(t => {
    select.innerHTML += `<option value="${t}">${t}</option>`;
  });

  if ([...select.options].some(o => o.value === currentValue)) {
    select.value = currentValue;
  }
}


function applyAlertFilters() {
  const severity = document.getElementById("alertSeverityFilter").value;
  const attack = document.getElementById("alertAttackFilter").value;
  const ip = document.getElementById("alertIpFilter").value.trim();

  let filtered = alerts;

  if (severity !== "ALL") {
    filtered = filtered.filter(
      a => severityText(a.severity) === severity
    );
  }

  if (attack !== "ALL") {
    filtered = filtered.filter(a => a.attack_type === attack);
  }

  if (ip) {
    filtered = filtered.filter(a => a.src_ip.includes(ip));
  }

  renderAlerts(filtered);
}

function renderAttackChart() {
  const counts = {};

  incidents.forEach(i => {
    counts[i.attack_type] = (counts[i.attack_type] || 0) + 1;
  });

  const labels = Object.keys(counts);
  const data = Object.values(counts);

  if (attackChart) attackChart.destroy();

  attackChart = new Chart(
    document.getElementById("attackChart"),
    {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Active Incidents",
          data
        }]
      }
    }
  );
}
function renderSeverityChart() {
  const levels = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  incidents.forEach(i => {
    levels[i.incident_severity]++;
  });

  if (severityChart) severityChart.destroy();

  severityChart = new Chart(
    document.getElementById("severityChart"),
    {
      type: "doughnut",
      data: {
        labels: Object.keys(levels),
        datasets: [{
          data: Object.values(levels)
        }]
      }
    }
  );
}
