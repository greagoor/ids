import React, { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import { fetchAuditLog, fetchAgentStatus } from '../lib/api'
import { CheckCircle, AlertCircle, Clock, Zap, Brain, Shield, Eye, Bug, Activity, Radio, GitBranch } from 'lucide-react'

const AGENT_ICONS = {
  detection_agent:     Zap,
  pretriage_agent:     Eye,
  investigation_agent: Brain,
  response_agent:      Shield,
  honeypot_agent:      Bug,
  learning_agent:      Activity,
  watchdog_agent:      Clock,
  firewall:            Shield,
}

const ACTION_COLORS = {
  ALERT_DETECTED:         'var(--accent-warning)',
  ROUTE_TO_INVESTIGATION: 'var(--accent-cyan)',
  ROUTE_TO_RESPONSE:      'var(--accent-warning)',
  INVESTIGATION_COMPLETE: 'var(--accent-purple)',
  BLOCK:                  'var(--accent-danger)',
  BLOCK_MOCK:             'var(--accent-danger)',
  RATE_LIMIT:             'var(--accent-warning)',
  RATE_LIMIT_MOCK:        'var(--accent-warning)',
  LOG_ONLY:               'var(--accent-success)',
  TOOL_FAILURE:           'var(--text-muted)',
  HONEYPOT_ROUTED:        '#f472b6',
  DRIFT_DETECTED:         '#fbbf24',
}

function AgentCard({ agent }) {
  const Icon = AGENT_ICONS[agent.agent_name] || Activity
  const isOld = agent.last_heartbeat &&
    (Date.now() - new Date(agent.last_heartbeat).getTime()) > 120000
  const statusColor = agent.status === 'BUSY' ? 'var(--accent-warning)'
    : agent.status === 'ERROR' ? 'var(--accent-danger)'
    : 'var(--accent-success)'

  return (
    <div className={`hud-card p-4 glow-hover ${isOld ? 'border-red-800/50' : ''}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon size={13} style={{color: statusColor, flexShrink:0}}/>
        <span className="text-xs font-medium truncate" style={{color:'var(--text-primary)'}}>
          {agent.agent_name.replace(/_/g,' ')}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          {/* Pulsing status dot */}
          <span
            className="w-2 h-2 rounded-full flex-shrink-0"
            style={{
              background: statusColor,
              boxShadow: `0 0 6px ${statusColor}`,
              animation: agent.status === 'BUSY' ? 'live-pulse 1.2s ease-in-out infinite' : 'none',
            }}
          />
          <span className="text-[9px] font-display font-semibold tracking-widest" style={{color: statusColor}}>
            {agent.status}
          </span>
        </div>
        {isOld && <span className="text-[9px]" style={{color:'var(--accent-danger)'}}>⚠ STALE</span>}
      </div>
      <p className="text-[9px] mono mt-2" style={{color:'var(--text-muted)'}}>
        {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleTimeString() : '—'}
      </p>
    </div>
  )
}

function AgentCardSkeleton() {
  return (
    <div className="hud-card p-4">
      <div className="skeleton h-3 w-28 mb-3 rounded"/>
      <div className="skeleton h-3 w-16 rounded"/>
    </div>
  )
}

function TimelineEntry({ entry, isNew }) {
  const Icon = AGENT_ICONS[entry.agent] || Activity
  const color = ACTION_COLORS[entry.action] || 'var(--text-secondary)'

  return (
    <div className={`flex gap-3 ${isNew ? 'flash-new' : ''}`} style={{borderRadius:8}}>
      <div className="flex flex-col items-center flex-shrink-0">
        <div className="w-8 h-8 rounded-full flex items-center justify-center"
          style={{
            background: `color-mix(in srgb, ${color} 12%, var(--bg-elevated))`,
            border: `1px solid color-mix(in srgb, ${color} 25%, var(--border-glass))`,
          }}>
          <Icon size={12} style={{color}}/>
        </div>
        <div className="w-px flex-1 mt-1" style={{background:'var(--border-glass)'}} />
      </div>

      <div className="pb-5 flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold" style={{color:'var(--text-primary)'}}>
            {entry.agent?.replace(/_/g,' ')}
          </span>
          <span className="text-xs font-display font-bold tracking-wide" style={{color}}>
            {entry.action?.replace(/_/g,' ')}
          </span>
          <span className="ml-auto mono text-[9px]" style={{color:'var(--text-muted)'}}>
            {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : ''}
          </span>
        </div>

        {entry.reasoning && (
          <p className="text-[11px] mt-1.5 leading-relaxed line-clamp-2" style={{color:'var(--text-secondary)'}}>
            {entry.reasoning}
          </p>
        )}

        {entry.metadata && (
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {entry.metadata.verdict !== undefined && entry.metadata.verdict !== null && (
              <span className="text-[9px] px-2 py-0.5 rounded font-mono"
                style={{background:'var(--border-glass)', color:'var(--text-secondary)'}}>
                verdict:{' '}
                {typeof entry.metadata.verdict === 'object'
                  ? (entry.metadata.verdict.attack_type || entry.metadata.verdict.recommended_action || 'see details')
                  : String(entry.metadata.verdict)}
              </span>
            )}
            {typeof entry.metadata.threat_score === 'number' && (
              <span className="text-[9px] px-2 py-0.5 rounded mono"
                style={{background:'var(--border-glass)', color:'var(--text-secondary)'}}>
                threat: {entry.metadata.threat_score}
              </span>
            )}
            {typeof entry.metadata.ml_score === 'number' && (
              <span className="text-[9px] px-2 py-0.5 rounded mono"
                style={{background:'var(--border-glass)', color:'var(--text-secondary)'}}>
                ml: {entry.metadata.ml_score.toFixed(3)}
              </span>
            )}
            {entry.metadata.mock === true && (
              <span className="text-[9px] px-2 py-0.5 rounded font-display tracking-wider"
                style={{background:'color-mix(in srgb, var(--accent-warning) 15%, transparent)', color:'var(--accent-warning)'}}>
                MOCK
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default function AgentTimeline() {
  const [entries, setEntries] = useState([])
  const [agents,  setAgents]  = useState([])
  const [loading, setLoading] = useState(true)
  const [newIds,  setNewIds]  = useState(new Set())

  // Initial load — same as original
  useEffect(() => {
    Promise.all([fetchAuditLog(150), fetchAgentStatus()]).then(([log, status]) => {
      setEntries(log.data || [])
      setAgents(status.data || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  // Realtime: audit_log inserts — same as original
  useEffect(() => {
    const ch = supabase
      .channel('audit-realtime')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'audit_log' }, payload => {
        setEntries(prev => [payload.new, ...prev].slice(0, 300))
        setNewIds(prev => new Set([...prev, payload.new.id]))
        setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(payload.new.id); return n }), 2000)
      })
      .subscribe()
    return () => supabase.removeChannel(ch)
  }, [])

  // Realtime: agent_status updates — same as original
  useEffect(() => {
    const ch = supabase
      .channel('agent-status-realtime')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'agent_status' }, payload => {
        setAgents(prev => {
          const idx = prev.findIndex(a => a.agent_name === payload.new.agent_name)
          if (idx >= 0) { const n = [...prev]; n[idx] = payload.new; return n }
          return [payload.new, ...prev]
        })
      })
      .subscribe()
    return () => supabase.removeChannel(ch)
  }, [])

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">
          Agent Timeline
        </h1>
        <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
          Live agent decisions and pipeline activity
        </p>
      </div>

      {/* Agent status grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-5 gap-4">
        {loading ? (
          Array.from({length:6}).map((_,i) => <AgentCardSkeleton key={i}/>)
        ) : agents.length === 0 ? (
          <div className="col-span-full empty-state">
            <Activity size={32}/>
            <p className="font-display text-[10px] tracking-widest">NO AGENTS REGISTERED</p>
            <p>Start <code className="mono">python run_agents.py</code> to bring agents online.</p>
          </div>
        ) : (
          agents.map(a => <AgentCard key={a.agent_name} agent={a}/>)
        )}
      </div>

      {/* Timeline — dominant full-width widget */}
      <div className="hud-card p-6">
        <div className="flex items-center gap-3 mb-6">
          <span className="live-dot"/>
          <p className="text-xs font-display font-semibold tracking-widest" style={{color:'var(--accent-cyan)'}}>
            LIVE ACTIVITY FEED
          </p>
          <Radio size={12} style={{color:'var(--accent-cyan)'}} className="animate-pulse-slow"/>
          <span className="ml-auto text-[10px]" style={{color:'var(--text-muted)'}}>
            {entries.length} events
          </span>
        </div>

        {loading ? (
          <div className="space-y-4">
            {Array.from({length:4}).map((_,i) => (
              <div key={i} className="flex gap-3">
                <div className="skeleton w-8 h-8 rounded-full flex-shrink-0"/>
                <div className="flex-1 space-y-2 pt-1">
                  <div className="skeleton h-3 w-48 rounded"/>
                  <div className="skeleton h-2.5 w-full rounded"/>
                </div>
              </div>
            ))}
          </div>
        ) : entries.length === 0 ? (
          <div className="empty-state">
            <GitBranch size={36}/>
            <p className="font-display text-[10px] tracking-widest">NO AGENT ACTIVITY YET</p>
            <p>Fire a simulation from the header bar to watch the pipeline in action.</p>
          </div>
        ) : (
          <div className="max-h-[60vh] overflow-y-auto pr-2">
            {entries.map((entry, i) => (
              <TimelineEntry key={entry.id || i} entry={entry} isNew={newIds.has(entry.id)} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
