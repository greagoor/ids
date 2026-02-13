import { SUPABASE_URL, API_KEY } from "./config.js";

/* ===============================
   1. AREA LINE CHART (Attacks Over Time)
================================= */
let timeChart;

export async function renderTimeChart() {

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/alerts?select=timestamp&order=timestamp.asc`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  const data = await res.json();

  const counts = {};

  data.forEach(row => {
    const time = new Date(row.timestamp);
    const label = time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    counts[label] = (counts[label] || 0) + 1;
  });

  const labels = Object.keys(counts);
  const values = Object.values(counts);

  if (timeChart) timeChart.destroy();

  const ctx = document.getElementById("timeChart").getContext("2d");

  const gradient = ctx.createLinearGradient(0, 0, 0, 400);
  gradient.addColorStop(0, "rgba(0,255,255,0.4)");
  gradient.addColorStop(1, "rgba(0,0,0,0)");

  timeChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Total Attacks Over Time",
        data: values,
        fill: true,
        backgroundColor: gradient,
        borderColor: "#00ffff",
        borderWidth: 2,
        tension: 0.4,
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false
    }
  });
}


/* ===============================
   2. HORIZONTAL BAR (Attack Types)
================================= */
let attackTypeChart;

export async function renderAttackTypeChart() {

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/attack_type_stats`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  const data = await res.json();

  const labels = data.map(row => row.attack_type);
  const values = data.map(row => row.total_alerts);

  if (attackTypeChart) attackTypeChart.destroy();

  attackTypeChart = new Chart(
    document.getElementById("attackTypeChart"),
    {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Total Alerts",
          data: values,
          backgroundColor: "rgba(255, 0, 128, 0.7)",
          borderColor: "#ff0080",
          borderWidth: 1,
          borderRadius: 8
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false
      }
    }
  );
}
