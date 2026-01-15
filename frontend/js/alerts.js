import { SUPABASE_URL, API_KEY } from "./config.js";

function getFilteredAlerts() {
  let data = alerts;

  if (alertFilterState.severity !== "ALL") {
    data = data.filter(
      a => severityText(a.severity) === alertFilterState.severity
    );
  }

  if (alertFilterState.attack !== "ALL") {
    data = data.filter(a => a.attack_type === alertFilterState.attack);
  }

  if (alertFilterState.ip) {
    data = data.filter(a => (a.src_ip || "").includes(alertFilterState.ip));
  }

  if (alertFilterState.minutes !== "ALL") {
    const cutoff =
      Date.now() - Number(alertFilterState.minutes) * 60 * 1000;
    data = data.filter(
      a => new Date(a.timestamp).getTime() >= cutoff
    );
  }

  return data;
}


export let alerts = [];

let alertFilterState = {
  severity: "ALL",
  attack: "ALL",
  ip: "",
  minutes: "ALL"
};




export async function loadAlerts() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/alerts_last_24h?limit=100`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  alerts = await res.json();

  populateAlertAttackTypes();

  document.getElementById("alertSeverityFilter").value =
    alertFilterState.severity;
  document.getElementById("alertAttackFilter").value =
    alertFilterState.attack;
  document.getElementById("alertIpFilter").value =
    alertFilterState.ip;
  document.getElementById("alertTimeFilter").value =
    alertFilterState.minutes;

  applyAlertFilters();   // ✅ single render path
}



function renderAlerts(data) {
  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = "";

  data.forEach(a => {
    tbody.innerHTML += `
      <tr>
        <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
        <td>${a.attack_type}</td>
        <td>${a.src_ip || "N/A"}</td>
        <td>${severityText(a.severity)}</td>
        <td>${a.confidence}</td>
        <td>${a.uri}</td>
      </tr>
    `;
  });
}

function severityText(sev) {
  return sev === 4 ? "CRITICAL" : sev === 3 ? "HIGH" : sev === 2 ? "MEDIUM" : "LOW";
}
export function initAlertFilters() {
  document.getElementById("alertSeverityFilter").onchange = applyAlertFilters;
  document.getElementById("alertAttackFilter").onchange = applyAlertFilters;
  document.getElementById("alertIpFilter").oninput = applyAlertFilters;
  document.getElementById("alertTimeFilter").onchange = applyAlertFilters;
  document
  .getElementById("exportAlertsBtn")
  .onclick = exportAlertsToCSV;
  document
  .getElementById("exportAlertsJsonBtn")
  .onclick = exportAlertsToJSON;


}

function populateAlertAttackTypes() {
  const select = document.getElementById("alertAttackFilter");
  const currentValue = alertFilterState.attack;

  const types = [...new Set(alerts.map(a => a.attack_type))];

  select.innerHTML = `<option value="ALL">ALL</option>`;
  types.forEach(t => {
    select.innerHTML += `<option value="${t}">${t}</option>`;
  });

  if ([...select.options].some(o => o.value === currentValue)) {
    select.value = currentValue;
  }
}


function applyAlertFilters() {
  alertFilterState.severity =
    document.getElementById("alertSeverityFilter").value;
  alertFilterState.attack =
    document.getElementById("alertAttackFilter").value;
  alertFilterState.ip =
    document.getElementById("alertIpFilter").value.trim();
  alertFilterState.minutes =
    document.getElementById("alertTimeFilter").value;

  let filtered = alerts;

  // 🔹 Severity
  if (alertFilterState.severity !== "ALL") {
    filtered = filtered.filter(
      a => severityText(a.severity) === alertFilterState.severity
    );
  }

  // 🔹 Attack type
  if (alertFilterState.attack !== "ALL") {
    filtered = filtered.filter(
      a => a.attack_type === alertFilterState.attack
    );
  }

  // 🔹 Source IP
  if (alertFilterState.ip) {
    filtered = filtered.filter(
      a => (a.src_ip || "").includes(alertFilterState.ip)
    );
  }

  // 🔹 Time range
  if (alertFilterState.minutes !== "ALL") {
    const cutoff =
      Date.now() - Number(alertFilterState.minutes) * 60 * 1000;

    filtered = filtered.filter(
      a => new Date(a.timestamp).getTime() >= cutoff
    );
  }

  renderAlerts(filtered);
}

function exportAlertsToCSV() {
  const data = getFilteredAlerts();   // ✅ SINGLE source of truth

  const headers = [
    "timestamp",
    "attack_type",
    "src_ip",
    "severity",
    "confidence",
    "uri"
  ];

  const rows = data.map(a => [
    a.timestamp,
    a.attack_type,
    a.src_ip || "",
    severityText(a.severity),
    a.confidence,
    `"${a.uri.replace(/"/g, '""')}"`
  ]);

  const csv =
    headers.join(",") + "\n" +
    rows.map(r => r.join(",")).join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `alerts_${new Date().toISOString()}.csv`;
  a.click();

  URL.revokeObjectURL(url);
}

function exportAlertsToJSON() {
  const data = getFilteredAlerts();

  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `alerts_${new Date().toISOString()}.json`;
  a.click();

  URL.revokeObjectURL(url);
}
