import React, { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import { fetchIncidents } from '../lib/api'
import { sendFeedback } from '../lib/api'
import { ChevronDown, ChevronRight, ThumbsUp, ThumbsDown, HelpCircle, AlertTriangle } from 'lucide-react'

const SEVERITY_COLORS = {
  CRITICAL: 'badge-critical',
  HIGH:     'badge-high',
  MEDIUM:   'badge-medium',
  LOW:      'badge-low',
}
const KILL_CHAIN_COLORS = {
  Reconnaissance: 'var(--accent-cyan)',
  Weaponization:  'var(--accent-purple)',
  Delivery:       '#eab308',
  Exploitation:   'var(--accent-warning)',
  Installation:   'var(--accent-danger)',
  'Command & Control': '#f472b6',
  Exfiltration:   'var(--accent-danger)',
}

function MitreChip({ tag }) {
  const id   = typeof tag === 'object' ? tag.technique_id : tag
  const name = typeof tag === 'object' ? tag.name : ''
  return (
    <span
      className="text-[9px] px-2 py-0.5 rounded font-mono"
      title={name}
      style={{
        background: 'color-mix(in srgb, var(--accent-purple) 12%, transparent)',
        color: 'var(--accent-purple)',
        border: '1px solid color-mix(in srgb, var(--accent-purple) 25%, transparent)',
      }}
    >
      {id}
    </span>
  )
}

function FeedbackButtons({ alertId }) {
  const [sent, setSent] = useState(null)
  const submit = async (verdict) => {
    setSent(verdict)
    await sendFeedback({ alertId, analyst: 'analyst', verdict })
  }
  if (sent) return (
    <span className="text-[10px] font-display tracking-widest" style={{color:'var(--accent-success)'}}>
      ✓ {sent} RECORDED
    </span>
  )
  return (
    <div className="flex gap-2">
      <button onClick={() => submit('TP')}
        className="reticle flex items-center gap-1.5 text-[10px] px-3 py-1.5 rounded-lg transition-all hover:scale-105"
        style={{background:'color-mix(in srgb, var(--accent-success) 12%, transparent)', color:'var(--accent-success)', border:'1px solid color-mix(in srgb, var(--accent-success) 25%, transparent)'}}>
        <ThumbsUp size={10}/> TRUE POS
      </button>
      <button onClick={() => submit('FP')}
        className="reticle flex items-center gap-1.5 text-[10px] px-3 py-1.5 rounded-lg transition-all hover:scale-105"
        style={{background:'color-mix(in srgb, var(--accent-danger) 12%, transparent)', color:'var(--accent-danger)', border:'1px solid color-mix(in srgb, var(--accent-danger) 25%, transparent)'}}>
        <ThumbsDown size={10}/> FALSE POS
      </button>
      <button onClick={() => submit('UNSURE')}
        className="reticle flex items-center gap-1.5 text-[10px] px-3 py-1.5 rounded-lg transition-all hover:scale-105"
        style={{background:'var(--border-glass)', color:'var(--text-muted)', border:'1px solid var(--border-glass)'}}>
        <HelpCircle size={10}/> UNSURE
      </button>
    </div>
  )
}

function IncidentRow({ incident }) {
  const [open, setOpen] = useState(false)
  const mitreTags = incident.mitre_tags || []
  const kc = incident.kill_chain_phase

  return (
    <div className="hud-card glow-hover mb-3 overflow-hidden">
      <div
        className="reticle flex items-center gap-3 px-5 py-4 cursor-pointer transition-colors"
        style={{'--hover-bg':'color-mix(in srgb, var(--accent-cyan) 4%, transparent)'}}
        onClick={() => setOpen(v => !v)}
        onMouseEnter={e => e.currentTarget.style.background='color-mix(in srgb, var(--accent-cyan) 4%, transparent)'}
        onMouseLeave={e => e.currentTarget.style.background='transparent'}
      >
        {open
          ? <ChevronDown size={13} style={{color:'var(--text-muted)', flexShrink:0}}/>
          : <ChevronRight size={13} style={{color:'var(--text-muted)', flexShrink:0}}/>
        }

        <span className={`text-[9px] px-2 py-0.5 rounded font-display font-semibold tracking-widest flex-shrink-0 ${SEVERITY_COLORS[incident.severity] || 'badge-info'}`}>
          {incident.severity}
        </span>

        <span className="mono text-sm font-medium w-32 flex-shrink-0" style={{color:'var(--text-primary)'}}>
          {incident.ip}
        </span>

        <span className="text-sm flex-1 truncate" style={{color:'var(--text-secondary)'}}>
          {incident.attack_type?.replace(/_/g,' ')}
        </span>

        <span className="text-xs flex-shrink-0 font-display" style={{color:'var(--text-muted)'}}>
          ×{incident.count}
        </span>

        {kc && (
          <span className="text-[9px] font-display font-semibold tracking-widest flex-shrink-0"
            style={{color: KILL_CHAIN_COLORS[kc] || 'var(--text-secondary)'}}>
            {kc}
          </span>
        )}

        <span
          className="text-[9px] px-2 py-0.5 rounded font-display font-semibold tracking-widest flex-shrink-0"
          style={{
            background: incident.status === 'ACTIVE'
              ? 'color-mix(in srgb, var(--accent-success) 12%, transparent)'
              : 'var(--border-glass)',
            color: incident.status === 'ACTIVE' ? 'var(--accent-success)' : 'var(--text-muted)',
            border: `1px solid ${incident.status === 'ACTIVE' ? 'color-mix(in srgb, var(--accent-success) 25%, transparent)' : 'var(--border-glass)'}`,
          }}
        >
          {incident.status}
        </span>
      </div>

      {open && (
        <div className="border-t px-5 py-5 space-y-4 animate-slide-in"
          style={{borderColor:'var(--border-glass)', background:'color-mix(in srgb, var(--bg-elevated) 50%, transparent)'}}>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>FIRST SEEN</p>
              <p className="mono" style={{color:'var(--text-primary)'}}>{new Date(incident.first_seen).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>LAST SEEN</p>
              <p className="mono" style={{color:'var(--text-primary)'}}>{new Date(incident.last_seen).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>THREAT SCORE</p>
              <p className="text-lg font-display font-bold" style={{color:'var(--accent-warning)'}}>
                {incident.threat_score?.toFixed(1) ?? '—'}
              </p>
            </div>
            <div>
              <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>KILL CHAIN</p>
              <p className="font-semibold text-xs" style={{color: KILL_CHAIN_COLORS[kc] || 'var(--text-secondary)'}}>
                {kc || '—'}
              </p>
            </div>
          </div>

          {mitreTags.length > 0 && (
            <div>
              <p className="text-[9px] font-display tracking-widest mb-2" style={{color:'var(--text-muted)'}}>
                MITRE ATT&CK TECHNIQUES
              </p>
              <div className="flex flex-wrap gap-1.5">
                {mitreTags.map((t,i) => <MitreChip key={i} tag={t}/>)}
              </div>
            </div>
          )}

          <div>
            <p className="text-[9px] font-display tracking-widest mb-2.5" style={{color:'var(--text-muted)'}}>
              ANALYST VERDICT
            </p>
            <FeedbackButtons alertId={incident.id}/>
          </div>
        </div>
      )}
    </div>
  )
}

function SkeletonRow() {
  return (
    <div className="hud-card mb-3 px-5 py-4 flex items-center gap-3">
      <div className="skeleton h-4 w-16 rounded flex-shrink-0"/>
      <div className="skeleton h-4 w-28 rounded flex-shrink-0"/>
      <div className="skeleton h-3 flex-1 rounded"/>
      <div className="skeleton h-4 w-16 rounded flex-shrink-0"/>
    </div>
  )
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [filter,    setFilter]    = useState('ALL')
  const [loading,   setLoading]   = useState(true)

  // Initial fetch — same as original
  useEffect(() => {
    fetchIncidents().then(r => { setIncidents(r.data || []); setLoading(false) })
  }, [])

  // Realtime — same as original
  useEffect(() => {
    const ch = supabase
      .channel('incidents-realtime')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'incidents' }, payload => {
        setIncidents(prev => {
          const idx = prev.findIndex(i => i.id === payload.new.id)
          if (idx >= 0) { const n=[...prev]; n[idx]=payload.new; return n }
          return [payload.new, ...prev]
        })
      })
      .subscribe()
    return () => supabase.removeChannel(ch)
  }, [])

  // Same derived data as original
  const filtered = filter === 'ALL' ? incidents : incidents.filter(i => i.status === filter)
  const grouped = {}
  filtered.forEach(i => { if (!grouped[i.ip]) grouped[i.ip]=[]; grouped[i.ip].push(i) })

  const active  = incidents.filter(i => i.status === 'ACTIVE').length
  const expired = incidents.filter(i => i.status === 'EXPIRED').length

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">Incidents</h1>
          <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
            Grouped by source IP · Click to expand details
          </p>
        </div>

        {/* Filter buttons */}
        <div className="flex gap-2">
          {['ALL','ACTIVE','EXPIRED'].map(s => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className="reticle text-[10px] px-4 py-2 rounded-lg font-display font-semibold tracking-widest transition-all"
              style={{
                background: filter === s
                  ? 'color-mix(in srgb, var(--accent-cyan) 12%, transparent)'
                  : 'var(--border-glass)',
                color: filter === s ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: `1px solid ${filter === s
                  ? 'color-mix(in srgb, var(--accent-cyan) 25%, transparent)'
                  : 'var(--border-glass)'}`,
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        {[
          {label:'TOTAL', value: incidents.length, color:'var(--accent-cyan)'},
          {label:'ACTIVE', value: active, color:'var(--accent-danger)'},
          {label:'EXPIRED', value: expired, color:'var(--text-muted)'},
        ].map(({label, value, color}) => (
          <div key={label} className="hud-card p-5 text-center">
            <p className="text-[9px] font-display tracking-widest mb-2" style={{color:'var(--text-muted)'}}>{label}</p>
            <p className="text-3xl font-display font-bold" style={{color}}>{value}</p>
          </div>
        ))}
      </div>

      {/* Incidents list */}
      {loading ? (
        <div className="space-y-0">
          {Array.from({length:5}).map((_,i) => <SkeletonRow key={i}/>)}
        </div>
      ) : Object.keys(grouped).length === 0 ? (
        <div className="empty-state hud-card py-20">
          <AlertTriangle size={40}/>
          <p className="font-display text-[10px] tracking-widest">NO INCIDENTS FOUND</p>
          <p>No incidents match the current filter. Try changing the filter above.</p>
        </div>
      ) : (
        Object.entries(grouped).map(([ip, incs]) => (
          <div key={ip} className="mb-4">
            <div className="flex items-center gap-2 mb-2 px-1">
              <div className="w-1 h-1 rounded-full" style={{background:'var(--accent-cyan)'}}/>
              <p className="text-xs mono" style={{color:'var(--accent-cyan)'}}>
                {ip}
              </p>
              <span className="text-[9px] font-display tracking-widest" style={{color:'var(--text-muted)'}}>
                · {incs.length} INCIDENT{incs.length > 1 ? 'S' : ''}
              </span>
            </div>
            {incs.map(inc => <IncidentRow key={inc.id} incident={inc}/>)}
          </div>
        ))
      )}
    </div>
  )
}
