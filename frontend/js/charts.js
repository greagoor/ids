let attackChart;
let severityChart;

export function renderAttackChart(incidents) {
  const counts = {};
  incidents.forEach(i => counts[i.attack_type] = (counts[i.attack_type] || 0) + 1);

  if (attackChart) attackChart.destroy();

  attackChart = new Chart(document.getElementById("attackChart"), {
    type: "bar",
    data: {
      labels: Object.keys(counts),
      datasets: [{ data: Object.values(counts) }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false
    }
  });
}

export function renderSeverityChart(incidents) {
  const levels = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  incidents.forEach(i => levels[i.incident_severity]++);

  if (severityChart) severityChart.destroy();

  severityChart = new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
      labels: Object.keys(levels),
      datasets: [{ data: Object.values(levels) }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false
    }
  });
}
