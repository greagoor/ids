import { SUPABASE_URL, API_KEY } from "./config.js";

/* =========================
   LOAD KPIs
========================= */
export async function loadKPIs() {
  try {
    await Promise.all([
      loadTotalAlerts(),
      loadActiveIncidents(),
      loadTopAttacker()
    ]);
  } catch (err) {
    console.error("KPI load error:", err);
  }
}

/* =========================
   TOTAL ALERTS
========================= */
async function loadTotalAlerts() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/alerts?select=id`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`,
        Prefer: "count=exact"
      }
    }
  );

  const count = res.headers.get("content-range")?.split("/")[1] || 0;

  document.getElementById("kpi-total").textContent = count;
}

/* =========================
   ACTIVE INCIDENTS
========================= */
async function loadActiveIncidents() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/incidents?select=id&status=eq.active`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`,
        Prefer: "count=exact"
      }
    }
  );

  const count = res.headers.get("content-range")?.split("/")[1] || 0;

  document.getElementById("kpi-incidents").textContent = count;
}

/* =========================
   TOP ATTACKER (24h view)
========================= */
async function loadTopAttacker() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/top_attacker_24h?limit=1`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  const data = await res.json();

  if (data.length > 0) {
    const attacker = data[0].src_ip;
    document.getElementById("kpi-success").textContent = attacker;
  } else {
    document.getElementById("kpi-success").textContent = "N/A";
  }
}
