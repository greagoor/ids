/**
 * lib/api.js — Direct Supabase queries
 *
 * FIX NOTES (2026-06-21):
 *  - fetchModelMetrics: was querying audit_log, now queries model_metrics table
 *  - fetchHoneypotLogs: was querying audit_log, now queries honeypot_logs table
 *  - fetchBlocklist: was querying audit_log BLOCK actions, now queries blocklist_cache
 *  - severity in alerts is an INTEGER (1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL) not a string
 */

import { supabase } from './supabase'

// ── Severity integer→string mapping (DB stores 1-4, not strings) ─────────────
export const SEVERITY_INT_MAP = {
  1: 'LOW',
  2: 'MEDIUM',
  3: 'HIGH',
  4: 'CRITICAL',
}

// ── Alerts ───────────────────────────────────────────────────────────────────
export async function fetchAlerts(limit = 50) {
  const result = await supabase
    .from('alerts')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit)
  return result
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

// ── Model metrics — reads from model_metrics table (NOT audit_log) ────────────
export async function fetchModelMetrics() {
  return supabase
    .from('model_metrics')
    .select('id, timestamp, accuracy, precision_score, recall_score, f1_score, drift_detected')
    .order('timestamp', { ascending: true })
    .limit(100)
}

// ── Honeypot logs — reads from honeypot_logs table (NOT audit_log) ────────────
export async function fetchHoneypotLogs(limit = 100) {
  return supabase
    .from('honeypot_logs')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit)
}

// ── Blocklist — reads from blocklist_cache table ──────────────────────────────
export async function fetchBlocklist() {
  return supabase
    .from('blocklist_cache')
    .select('ip, source, score, blocked_until, created_at')
    .order('created_at', { ascending: false })
    .limit(100)
}

// ── Investigation report for a specific alert_uuid ────────────────────────────
// The alerts table does NOT have investigation_verdict/shap_features columns.
// They live in audit_log.metadata (agent=investigation_agent) keyed by alert_id.
export async function fetchInvestigationForAlert(alertUuid) {
  if (!alertUuid) return { data: null, error: null }
  const { data, error } = await supabase
    .from('audit_log')
    .select('reasoning, metadata, timestamp')
    .eq('agent', 'investigation_agent')
    .eq('alert_id', alertUuid)
    .order('timestamp', { ascending: false })
    .limit(1)
  if (error || !data || data.length === 0) return { data: null, error }
  return { data: data[0], error: null }
}

// ── Feedback ──────────────────────────────────────────────────────────────────
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
  })
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }
  return await response.json()
}

// ── Simulate attack ───────────────────────────────────────────────────────────
export async function simulateAttack(attackType) {
  const demoAlert = {
    agent: 'detection_agent',
    action: 'ALERT_DETECTED',
    reasoning: `[SIMULATED] ${attackType} attack from demo button`,
    metadata: { attack_type: attackType, verdict: 'HIGH', ml_score: 0.91, source: 'demo' },
    alert_id: crypto.randomUUID(),
  }
  return supabase.from('audit_log').insert(demoAlert)
}

// ── Ingest trigger ────────────────────────────────────────────────────────────
export async function triggerIngest() {
  return { data: { status: 'ingest requires FastAPI server on port 8000' }, error: null }
}
