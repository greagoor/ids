import React, { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import { fetchHoneypotLogs, fetchBlocklist } from '../lib/api'
import { Bug, Lock, AlertTriangle, Radio, ShieldOff } from 'lucide-react'

function HpRow({ log, isNew }) {
  return (
    <div
      className={`flex items-center gap-3 px-4 py-2.5 rounded-lg text-xs transition-all hover:scale-[1.002] ${isNew ? 'flash-new' : ''}`}
      style={{
        background: 'color-mix(in srgb, var(--bg-elevated) 60%, transparent)',
        border: '1px solid color-mix(in srgb, #f472b6 12%, var(--border-glass))',
      }}
    >
      <Bug size={11} style={{color:'#f472b6', flexShrink:0}}/>
      <span className="mono font-medium w-32 flex-shrink-0" style={{color:'#f472b6'}}>
        {log.ip}
      </span>
      <span className="font-semibold w-28 flex-shrink-0" style={{color:'var(--accent-cyan)'}}>
        {log.endpoint}
      </span>
      <span className="flex-1 truncate mono" style={{color:'var(--text-muted)'}}>
        {log.payload ? log.payload.slice(0, 80) : '—'}
      </span>
      <span className="mono whitespace-nowrap" style={{color:'var(--text-muted)', fontSize:'0.68rem'}}>
        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}
      </span>
    </div>
  )
}

function BlockedRow({ entry }) {
  const until   = entry.blocked_until ? new Date(entry.blocked_until) : null
  const expired = until && until < new Date()
  const score   = entry.score ?? 0

  return (
    <div
      className="flex items-center gap-3 px-4 py-3 rounded-lg text-xs transition-all"
      style={{
        background: expired
          ? 'color-mix(in srgb, var(--bg-elevated) 30%, transparent)'
          : 'color-mix(in srgb, var(--accent-danger) 8%, var(--bg-elevated))',
        border: `1px solid ${expired
          ? 'var(--border-glass)'
          : 'color-mix(in srgb, var(--accent-danger) 20%, transparent)'}`,
        opacity: expired ? 0.5 : 1,
      }}
    >
      <Lock size={11} style={{color: expired ? 'var(--text-muted)' : 'var(--accent-danger)', flexShrink:0}}/>

      <span className="mono font-medium w-32 flex-shrink-0"
        style={{color: expired ? 'var(--text-muted)' : 'var(--accent-danger)'}}>
        {entry.ip}
      </span>

      <span className="w-24 flex-shrink-0" style={{color:'var(--accent-warning)'}}>
        {entry.source}
      </span>

      {/* Score bar */}
      <div className="flex items-center gap-2 w-32 flex-shrink-0">
        <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{background:'var(--bg-elevated)'}}>
          <div className="h-full rounded-full transition-all"
            style={{
              width:`${score}%`,
              background: score >= 90 ? 'var(--accent-danger)' : score >= 70 ? 'var(--accent-warning)' : 'var(--accent-success)',
            }}/>
        </div>
        <span className="font-display font-bold text-[10px] w-12"
          style={{color: score >= 90 ? 'var(--accent-danger)' : 'var(--accent-warning)'}}>
          {score}/100
        </span>
      </div>

      <span className="flex-1 text-right"
        style={{color: expired ? 'var(--text-muted)' : 'var(--accent-danger)'}}>
        {expired ? 'EXPIRED' : `until ${until?.toLocaleString()}`}
      </span>
    </div>
  )
}

function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg" style={{border:'1px solid var(--border-glass)'}}>
      <div className="skeleton w-3 h-3 rounded flex-shrink-0"/>
      <div className="skeleton h-3 w-28 rounded flex-shrink-0"/>
      <div className="skeleton h-3 w-24 rounded flex-shrink-0"/>
      <div className="skeleton h-3 flex-1 rounded"/>
    </div>
  )
}

export default function HoneypotLogs() {
  const [logs,      setLogs]      = useState([])
  const [blocklist, setBlocklist] = useState([])
  const [loading,   setLoading]   = useState(true)
  const [tab,       setTab]       = useState('hits')
  const [newIds,    setNewIds]    = useState(new Set())

  // Same fetch as original
  useEffect(() => {
    Promise.all([fetchHoneypotLogs(200), fetchBlocklist()]).then(([hp, bl]) => {
      setLogs(hp.data || [])
      setBlocklist(bl.data || [])
      setLoading(false)
    })
  }, [])

  // Realtime honeypot_logs — same as original
  useEffect(() => {
    const ch = supabase
      .channel('honeypot-realtime')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'honeypot_logs' }, payload => {
        setLogs(prev => [payload.new, ...prev].slice(0, 300))
        setNewIds(prev => new Set([...prev, payload.new.id]))
        setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(payload.new.id); return n }), 2000)
      })
      .subscribe()
    return () => supabase.removeChannel(ch)
  }, [])

  // Same derived data as original
  const endpointCounts = {}
  logs.forEach(l => { endpointCounts[l.endpoint] = (endpointCounts[l.endpoint] || 0) + 1 })
  const sortedEndpoints = Object.entries(endpointCounts).sort((a,b) => b[1]-a[1])

  const uniqueIps = [...new Set(logs.map(l => l.ip))].length

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">Honeypot Monitor</h1>
        <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
          Trap endpoint hits · auto-blocklist promotions
        </p>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
        {[
          { label: 'TOTAL HITS',    value: logs.length,                                         color: '#f472b6',              icon: Bug },
          { label: 'UNIQUE IPS',    value: uniqueIps,                                           color: 'var(--accent-warning)',icon: AlertTriangle },
          { label: 'AUTO-BLOCKED',  value: blocklist.filter(b => b.source === 'honeypot').length, color: 'var(--accent-danger)', icon: Lock },
          { label: 'ACTIVE BLOCKS', value: blocklist.length,                                    color: '#eab308',              icon: ShieldOff },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="hud-card p-6 glow-hover">
            <div className="flex items-start justify-between mb-3">
              <p className="text-[10px] font-display font-semibold tracking-widest" style={{color:'var(--text-muted)'}}>
                {label}
              </p>
              <Icon size={14} style={{color, flexShrink:0}}/>
            </div>
            <p className="text-3xl font-display font-bold" style={{color}}>{value}</p>
          </div>
        ))}
      </div>

      {/* Endpoint frequency bars */}
      {sortedEndpoints.length > 0 && (
        <div className="hud-card p-6">
          <p className="text-[10px] font-display font-semibold tracking-widest mb-5" style={{color:'var(--text-muted)'}}>
            MOST TARGETED HONEYPOT ENDPOINTS
          </p>
          <div className="space-y-3">
            {sortedEndpoints.map(([ep, count]) => {
              const pct = (count / logs.length) * 100
              return (
                <div key={ep} className="flex items-center gap-3 text-xs">
                  <span className="mono font-semibold w-28 flex-shrink-0" style={{color:'var(--accent-cyan)'}}>
                    {ep}
                  </span>
                  <div className="flex-1 rounded-full h-2 overflow-hidden" style={{background:'var(--bg-elevated)'}}>
                    <div className="h-full rounded-full transition-all"
                      style={{width:`${pct}%`, background:'#f472b6', opacity:0.75}}/>
                  </div>
                  <span className="w-8 text-right font-display font-bold" style={{color:'#f472b6'}}>
                    {count}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Tabbed hits / blocklist — dominant full-width card */}
      <div className="hud-card overflow-hidden">
        {/* Tab bar */}
        <div className="flex border-b" style={{borderColor:'var(--border-glass)'}}>
          {[
            ['hits',      '🪤 Honeypot Hits', logs.length],
            ['blocklist', '🔒 Blocklist',      blocklist.length],
          ].map(([key, label, count]) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className="px-5 py-3.5 text-[10px] font-display font-semibold tracking-widest transition-all border-b-2 flex items-center gap-2"
              style={{
                borderColor: tab === key ? 'var(--accent-cyan)' : 'transparent',
                color: tab === key ? 'var(--accent-cyan)' : 'var(--text-muted)',
                background: tab === key ? 'color-mix(in srgb, var(--accent-cyan) 4%, transparent)' : 'transparent',
              }}
            >
              {label}
              <span className="px-1.5 py-0.5 rounded text-[9px]"
                style={{
                  background: tab === key
                    ? 'color-mix(in srgb, var(--accent-cyan) 15%, transparent)'
                    : 'var(--border-glass)',
                  color: tab === key ? 'var(--accent-cyan)' : 'var(--text-muted)',
                }}>
                {count}
              </span>
            </button>
          ))}

          {/* LIVE indicator */}
          <div className="ml-auto flex items-center gap-2 px-4">
            <span className="live-dot" style={{width:6,height:6}}/>
            <span className="font-display text-[9px] tracking-widest" style={{color:'var(--accent-success)'}}>
              LIVE
            </span>
            <Radio size={10} style={{color:'var(--accent-success)'}} className="animate-pulse-slow"/>
          </div>
        </div>

        <div className="p-6">
          {loading ? (
            <div className="space-y-2">
              {Array.from({length:5}).map((_,i) => <SkeletonRow key={i}/>)}
            </div>
          ) : tab === 'hits' ? (
            logs.length === 0 ? (
              <div className="empty-state">
                <Bug size={40}/>
                <p className="font-display text-[10px] tracking-widest">NO HONEYPOT HITS YET</p>
                <p>Try visiting <code className="mono">localhost:8000/admin</code> or <code className="mono">localhost:8000/.env</code> to trigger a hit.</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {logs.map((l, i) => (
                  <HpRow key={l.id || i} log={l} isNew={newIds.has(l.id)}/>
                ))}
              </div>
            )
          ) : (
            blocklist.length === 0 ? (
              <div className="empty-state">
                <Lock size={40}/>
                <p className="font-display text-[10px] tracking-widest">NO ACTIVE BLOCKS</p>
                <p>IPs are auto-promoted to the blocklist after hitting 2+ distinct honeypot endpoints.</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {blocklist.map((b, i) => <BlockedRow key={b.id || i} entry={b}/>)}
              </div>
            )
          )}
        </div>
      </div>
    </div>
  )
}
