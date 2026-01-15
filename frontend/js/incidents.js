import { SUPABASE_URL, API_KEY } from "./config.js";
import { renderAttackChart, renderSeverityChart } from "./charts.js";
import { openIncidentModal } from "./modal.js";

export let incidents = [];
let incidentFilterState = {
  severity: "ALL",
  attack: "ALL",
  ip: ""
};

/* =========================
   LOAD INCIDENTS FROM API
   ========================= */
export async function loadIncidents() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/active_incidents`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  incidents = await res.json();

  
  
  populateAttackTypes();

document.getElementById("severityFilter").value =
  incidentFilterState.severity;
document.getElementById("attackFilter").value =
  incidentFilterState.attack;
document.getElementById("ipFilter").value =
  incidentFilterState.ip;

applyFilters();

renderAttackChart(incidents);
  renderSeverityChart(incidents);

}

/* =========================
   RENDER INCIDENT TABLE
   ========================= */
function renderIncidents(data) {
  const tbody = document.querySelector("#incidents tbody");
  tbody.innerHTML = "";

  data.forEach(i => {
    const row = document.createElement("tr");

    row.className = "incident-row";
    row.dataset.ip = i.src_ip || "";
    row.dataset.attack = i.attack_type;

    row.innerHTML = `
      <td>${i.attack_type}</td>
      <td>${i.src_ip || "N/A"}</td>
      <td class="sev-${i.incident_severity}">
        ${i.incident_severity}
      </td>
      <td>${i.alert_count}</td>
      <td>${new Date(i.last_seen).toLocaleString()}</td>
    `;

    /* =========================
       CLICK → OPEN MODAL
       ========================= */
    row.onclick = () => {
      openIncidentModal(
        i.src_ip || "",
        i.attack_type
      );
    };

    tbody.appendChild(row);
  });
}
export function initIncidentFilters() {
  document.getElementById("severityFilter").onchange = applyFilters;
  document.getElementById("attackFilter").onchange = applyFilters;
  document.getElementById("ipFilter").oninput = applyFilters;
}
function applyFilters() {
  incidentFilterState.severity =
    document.getElementById("severityFilter").value;
  incidentFilterState.attack =
    document.getElementById("attackFilter").value;
  incidentFilterState.ip =
    document.getElementById("ipFilter").value.trim();

  let filtered = incidents;

  if (incidentFilterState.severity !== "ALL") {
    filtered = filtered.filter(
      i => i.incident_severity === incidentFilterState.severity
    );
  }

  if (incidentFilterState.attack !== "ALL") {
    filtered = filtered.filter(
      i => i.attack_type === incidentFilterState.attack
    );
  }

  if (incidentFilterState.ip) {
    filtered = filtered.filter(
      i => (i.src_ip || "").includes(incidentFilterState.ip)
    );
  }

  renderIncidents(filtered);
}

function populateAttackTypes() {
  const select = document.getElementById("attackFilter");
  const currentValue = incidentFilterState.attack;

  const types = [...new Set(incidents.map(i => i.attack_type))];

  select.innerHTML = `<option value="ALL">ALL</option>`;
  types.forEach(t => {
    select.innerHTML += `<option value="${t}">${t}</option>`;
  });

  // restore selection if still valid
  if ([...select.options].some(o => o.value === currentValue)) {
    select.value = currentValue;
  }
}
