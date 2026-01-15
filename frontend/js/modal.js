import { SUPABASE_URL, API_KEY } from "./config.js";
export let modalOpen = false;

export async function openIncidentModal(src_ip, attack_type) {
modalOpen   = true
  const modal = document.getElementById("incidentModal");
  modal.classList.remove("hidden");
  const title = document.getElementById("modalTitle");
  const tbody = document.querySelector("#modalAlerts tbody");

  title.textContent = `Incident: ${attack_type} from ${src_ip || "N/A"}`;
  tbody.innerHTML = "";

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/alerts_last_24h?src_ip=eq.${src_ip}&attack_type=eq.${attack_type}`,
    {
      headers: {
        apikey: API_KEY,
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  const alerts = await res.json();

  alerts.forEach(a => {
    tbody.innerHTML += `
      <tr>
        <td>${new Date(a.timestamp).toLocaleString()}</td>
        <td>${severityText(a.severity)}</td>
        <td>${a.confidence}</td>
        <td>${a.uri}</td>
      </tr>
    `;
  });

  modal.classList.remove("hidden");

  document.getElementById("closeModal").onclick = () =>
    modal.classList.add("hidden");
   
}

function severityText(sev) {
  return sev === 4 ? "CRITICAL" :
         sev === 3 ? "HIGH" :
         sev === 2 ? "MEDIUM" : "LOW";
}
