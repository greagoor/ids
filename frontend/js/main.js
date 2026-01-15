import { loadIncidents, initIncidentFilters } from "./incidents.js";
import { loadAlerts, initAlertFilters } from "./alerts.js";
import { modalOpen } from "./modal.js";

async function loadPartial(id, file) {
  const res = await fetch(`partials/${file}`);
  document.getElementById(id).innerHTML = await res.text();
}

async function init() {
  await loadPartial("charts", "charts.html");
  await loadPartial("alerts", "alerts.html");
  await loadPartial("incidents", "incidents.html");
  await loadPartial("modal", "incidents_modal.html");

  // 🔑 NOW elements exist
  initAlertFilters();
  initIncidentFilters();

setupNavigation();
  loadIncidents(); 
  loadAlerts();

  setInterval(() => {
    if (!modalOpen) {
      loadIncidents();
      loadAlerts();
      

    }
  }, 5000);
}

init();
function setupNavigation() {
  const buttons = document.querySelectorAll(".sidebar button");
  const views = document.querySelectorAll(".view");

  buttons.forEach(btn => {
    btn.onclick = () => {
      const target = btn.dataset.view;

      views.forEach(v => v.classList.add("hidden"));
      document.getElementById(target).classList.remove("hidden");
    };
  });
}

