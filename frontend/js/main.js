import { loadIncidents, initIncidentFilters } from "./incidents.js";
import { loadAlerts, initAlertFilters } from "./alerts.js";
import { renderTimeChart, renderAttackTypeChart } from "./charts.js";
import { modalOpen } from "./modal.js";

async function loadPartial(id, file) {
  const res = await fetch(`/frontend/partials/${file}`);
  document.getElementById(id).innerHTML = await res.text();
}


async function init() {

  // Load all partials first
  await loadPartial("charts", "charts.html");
  await loadPartial("alerts", "alerts.html");
  await loadPartial("incidents", "incidents.html");
  await loadPartial("modal", "incidents_modal.html");

  // Now canvases exist → initialize charts
  await renderTimeChart();
  await renderAttackTypeChart();

  // Initialize filters
  initAlertFilters();
  initIncidentFilters();

  // Setup navigation
  setupNavigation();

  // Initial data load
  loadIncidents();
  loadAlerts();

  // Auto refresh every 5 seconds
  setInterval(async () => {
    if (!modalOpen) {
      loadIncidents();
      loadAlerts();

      // Refresh charts too
      await renderTimeChart();
      await renderAttackTypeChart();
    }
  }, 5000);
}

function setupNavigation() {
  const buttons = document.querySelectorAll(".sidebar button");
  const views = document.querySelectorAll(".view");

  buttons.forEach(btn => {
    btn.onclick = () => {
      const target = btn.dataset.view;

      views.forEach(v => v.classList.add("hidden"));
      document.getElementById(target).classList.remove("hidden");

      buttons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
    };
  });
}

init();
