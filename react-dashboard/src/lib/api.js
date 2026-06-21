/**
 * lib/api.js — Direct Supabase queries (no FastAPI dependency)
 *
 * Previously routed through http://localhost:8000 (FastAPI).
 * Now uses the supabase-js client directly so the dashboard works
 * with only the Vite dev server running.
 *
 * Realtime subscriptions in each page component remain unchanged —
 * they already use the same supabase client.
 */

import { supabase } from './supabase'

// ── Alerts ───────────────────────────────────────────────────────────────────
export async function fetchAlerts(limit = 50) {
  const result = await supabase
    .from('alerts')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit)
  return result   // { data, error } — same shape pages expect
}

// ── Incidents ────────────────────────────────────────────────────────────────
export async function fetchIncidents(status = null) {
  let query = supabase.from('incidents').select('*').order('last_seen', { ascending: false })
  if (status) query = query.eq('status', status)
  return query
}

// ── Agent status ─────────────────────────────────────────────────────────────
export async function fetchAgentStatus() {
  return supabase
    .from('agent_status')
    .select('*')
    .order('last_heartbeat', { ascending: false })
}

// ── Audit log ─────────────────────────────────────────────────────────────────
export async function fetchAuditLog(limit = 100, agent = null) {
  let query = supabase
    .from('audit_log')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit)
  if (agent) query = query.eq('agent', agent)
  return query
}

// ── System health (derived from agent_status) ─────────────────────────────────
export async function fetchSystemHealth() {
  const { data, error } = await supabase.from('agent_status').select('*')
  if (error) return { data: null, error }
  const healthy = (data || []).filter(a => a.status !== 'ERROR').length
  return { data: { total_agents: (data||[]).length, healthy, error_agents: (data||[]).length - healthy }, error: null }
}

// ── Model metrics (from audit_log aggregation) ────────────────────────────────
export async function fetchModelMetrics() {
  return supabase
    .from('audit_log')
    .select('action, metadata, timestamp')
    .order('timestamp', { ascending: false })
    .limit(500)
}

// ── Honeypot logs ─────────────────────────────────────────────────────────────
export async function fetchHoneypotLogs(limit = 100) {
  return supabase
    .from('audit_log')
    .select('*')
    .eq('agent', 'honeypot_agent')
    .order('timestamp', { ascending: false })
    .limit(limit)
}

// ── Blocklist (from incidents + audit_log BLOCK actions) ──────────────────────
export async function fetchBlocklist() {
  return supabase
    .from('audit_log')
    .select('alert_id, reasoning, metadata, timestamp')
    .in('action', ['BLOCK', 'BLOCK_MOCK', 'BLOCK_REFUSED'])
    .order('timestamp', { ascending: false })
    .limit(100)
}

// ── Feedback (stub — no direct table without FastAPI) ─────────────────────────
export async function sendFeedback({ alertId, analyst, verdict, notes }) {
  return supabase.from('audit_log').insert({
    agent: 'analyst',
    action: 'ANALYST_FEEDBACK',
    reasoning: notes,
    metadata: { alert_id: alertId, analyst, verdict },
    alert_id: alertId,
  })
}

// ── Chat (Routed to FastAPI backend) ─────────
export async function sendChat({ query, analystRole }) {
  const response = await fetch('http://127.0.0.1:8000/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, analyst_role: analystRole })
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return await response.json();
}

// ── Simulate attack via _bridge_pipeline (stub — returns dummy for demo) ──────
export async function simulateAttack(attackType) {
  // Without FastAPI, insert a direct audit_log row as a demo event
  const demoAlert = {
    agent: 'detection_agent',
    action: 'ALERT_DETECTED',
    reasoning: `[SIMULATED] ${attackType} attack from demo button`,
    metadata: { attack_type: attackType, verdict: 'HIGH', ml_score: 0.91, source: 'demo' },
    alert_id: crypto.randomUUID(),
  }
  return supabase.from('audit_log').insert(demoAlert)
}

// ── Ingest trigger stub ───────────────────────────────────────────────────────
export async function triggerIngest() {
  return { data: { status: 'ingest requires FastAPI server on port 8000' }, error: null }
}
