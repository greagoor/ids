import React, { useEffect, useState } from 'react'
import { fetchAlerts, fetchModelMetrics } from '../lib/api'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { Brain, TrendingUp, AlertTriangle } from 'lucide-react'

function ShapBar({ feature, value, impact }) {
  const pct = Math.min(Math.abs(impact) * 300, 100)
  const positive = impact >= 0
  return (
    <div className="flex items-center gap-3 py-2">
      <span className="text-[11px] mono w-44 truncate" style={{color:'var(--text-secondary)'}} title={feature}>
        {feature}
      </span>
      <div className="flex-1 rounded-full h-1.5 overflow-hidden" style={{background:'var(--bg-elevated)'}}>
        <div
          className="h-full rounded-full transition-all"
          style={{width:`${pct}%`, background: positive ? 'var(--accent-danger)' : 'var(--accent-success)'}}
        />
      </div>
      <span className="text-[10px] mono w-16 text-right"
        style={{color: positive ? 'var(--accent-danger)' : 'var(--accent-success)'}}>
        {impact >= 0 ? '+' : ''}{impact.toFixed(4)}
      </span>
      <span className="text-[10px] mono w-12 text-right" style={{color:'var(--text-muted)'}}>
        (={value})
      </span>
    </div>
  )
}

function AlertSelector({ alerts, selected, onSelect }) {
  return (
    <select
      value={selected?.id || ''}
      onChange={e => onSelect(alerts.find(a => a.id === e.target.value))}
      className="w-full rounded-lg px-3 py-2.5 text-sm focus:outline-none"
      style={{
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-glass)',
        color: 'var(--text-primary)',
        fontFamily: 'JetBrains Mono, monospace',
      }}
    >
      <option value="">— Select an alert —</option>
      {alerts.map(a => (
        <option key={a.id} value={a.id}>
          [{a.severity}] {a.attack_type} · {a.ip || a.src_ip} · {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ''}
        </option>
      ))}
    </select>
  )
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="glass px-3 py-2 text-xs">
      <p className="font-display text-[9px] tracking-wider mb-1" style={{color:'var(--text-muted)'}}>
        {new Date(label).toLocaleDateString()}
      </p>
      {payload.map((p,i) => (
        <p key={i} style={{color: p.color}}>
          {p.name}: <span className="font-bold">{(p.value * 100).toFixed(1)}%</span>
        </p>
      ))}
    </div>
  )
}

export default function AiPanel() {
  const [alerts,   setAlerts]   = useState([])
  const [metrics,  setMetrics]  = useState([])
  const [selected, setSelected] = useState(null)
  const [loading,  setLoading]  = useState(true)

  // Same data fetching as original
  useEffect(() => {
    Promise.all([fetchAlerts(100), fetchModelMetrics()]).then(([al, mt]) => {
      const alertData = al.data || []
      setAlerts(alertData)
      setMetrics((mt.data || []).reverse())
      if (alertData.length > 0) setSelected(alertData[0])
      setLoading(false)
    })
  }, [])

  // Same derived data as original
  const shap      = selected?.shap_features || []
  const invVerdict = selected?.investigation_verdict

  const repColor = invVerdict?.ip_reputation === 'MALICIOUS' ? 'var(--accent-danger)'
    : invVerdict?.ip_reputation === 'SUSPICIOUS' ? 'var(--accent-warning)'
    : 'var(--accent-success)'

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">AI Panel</h1>
        <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
          SHAP explainability · Gemini investigation reports · Model drift metrics
        </p>
      </div>

      {/* Alert selector */}
      <div className="hud-card p-6">
        <p className="text-[10px] font-display font-semibold tracking-widest mb-4" style={{color:'var(--text-muted)'}}>
          SELECT ALERT TO INSPECT
        </p>
        {loading ? (
          <div className="skeleton h-10 w-full rounded-lg"/>
        ) : (
          <AlertSelector alerts={alerts} selected={selected} onSelect={setSelected}/>
        )}
      </div>

      {selected && (
        <>
          {/* Alert metadata */}
          <div className="hud-card p-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-5 text-xs mb-0">
              {[
                {label:'IP ADDRESS', value: selected.ip || selected.src_ip, color:'var(--text-primary)', mono:true},
                {label:'ATTACK TYPE', value: selected.attack_type, color:'var(--accent-warning)'},
                {label:'SUSPICION SCORE', value: `${((selected.suspicion_score||0)*100).toFixed(1)}%`, color:'var(--accent-cyan)', large:true},
                {label:'VERDICT', value: selected.verdict||'—', color:`var(--accent-${(selected.verdict||'low').toLowerCase()==='critical'?'danger':(selected.verdict||'').toLowerCase()==='high'?'warning':'success'})`},
              ].map(({label,value,color,mono,large}) => (
                <div key={label}>
                  <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>{label}</p>
                  <p className={`${large?'text-2xl font-display font-bold':'font-semibold'} ${mono?'mono':''}`} style={{color}}>{value}</p>
                </div>
              ))}
            </div>
            {selected.url && (
              <div className="mt-4 pt-4 border-t" style={{borderColor:'var(--border-glass)'}}>
                <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>URL</p>
                <p className="mono text-[11px] break-all line-clamp-2" style={{color:'var(--text-secondary)'}}>{selected.url}</p>
              </div>
            )}
          </div>

          {/* SHAP features */}
          {shap.length > 0 && (
            <div className="hud-card p-6">
              <div className="flex items-center gap-2 mb-5">
                <Brain size={14} style={{color:'var(--accent-purple)'}}/>
                <p className="text-[10px] font-display font-semibold tracking-widest" style={{color:'var(--text-muted)'}}>
                  TOP SHAP FEATURES
                </p>
                <span className="ml-auto text-[9px]" style={{color:'var(--text-muted)'}}>
                  red = suspicious · green = benign signal
                </span>
              </div>
              <div>
                {shap.map((f, i) => (
                  <ShapBar key={i} feature={f.feature} value={f.value} impact={f.impact || 0} />
                ))}
              </div>
            </div>
          )}

          {/* Gemini investigation report */}
          {invVerdict ? (
            <div className="hud-card p-6">
              <div className="flex items-center gap-2 mb-5">
                <Brain size={14} style={{color:'var(--accent-cyan)'}}/>
                <p className="text-[10px] font-display font-semibold tracking-widest" style={{color:'var(--text-muted)'}}>
                  GEMINI INVESTIGATION REPORT
                </p>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5 text-xs">
                <div>
                  <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>CONFIDENCE</p>
                  <p className="font-bold text-lg font-display" style={{color:'var(--accent-cyan)'}}>
                    {((invVerdict.confidence||0)*100).toFixed(0)}%
                  </p>
                </div>
                <div>
                  <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>THREAT SCORE</p>
                  <p className="font-bold text-lg font-display" style={{color:'var(--accent-warning)'}}>
                    {invVerdict.threat_score?.toFixed(1)}
                  </p>
                </div>
                <div>
                  <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>IP REPUTATION</p>
                  <p className="font-semibold" style={{color: repColor}}>{invVerdict.ip_reputation}</p>
                </div>
                <div>
                  <p className="text-[9px] font-display tracking-widest mb-1.5" style={{color:'var(--text-muted)'}}>RECOMMENDED</p>
                  <p className="font-semibold" style={{color:'var(--accent-purple)'}}>{invVerdict.recommended_action}</p>
                </div>
              </div>
              {invVerdict.evidence_summary && (
                <div className="p-4 rounded-lg mb-4"
                  style={{background:'var(--bg-elevated)', border:'1px solid var(--border-glass)'}}>
                  <p className="text-[11px] leading-relaxed" style={{color:'var(--text-secondary)'}}>
                    {invVerdict.evidence_summary}
                  </p>
                </div>
              )}
              {invVerdict.mitre_tags?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {invVerdict.mitre_tags.map((t,i) => (
                    <span key={i} className="text-[9px] px-2 py-0.5 rounded mono"
                      style={{background:'color-mix(in srgb, var(--accent-purple) 12%, transparent)', color:'var(--accent-purple)', border:'1px solid color-mix(in srgb, var(--accent-purple) 25%, transparent)'}}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="hud-card p-6" style={{borderStyle:'dashed'}}>
              <div className="empty-state">
                <Brain size={32}/>
                <p className="font-display text-[10px] tracking-widest">NO INVESTIGATION REPORT</p>
                <p>This alert may still be in-flight through the agent pipeline.</p>
              </div>
            </div>
          )}
        </>
      )}

      {/* Model metrics chart */}
      {metrics.length > 0 && (
        <div className="hud-card p-6">
          <div className="flex items-center gap-2 mb-5">
            <TrendingUp size={14} style={{color:'var(--accent-success)'}}/>
            <p className="text-[10px] font-display font-semibold tracking-widest" style={{color:'var(--text-muted)'}}>
              MODEL PERFORMANCE METRICS
            </p>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={metrics} margin={{top:0,right:0,left:-20,bottom:0}}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-glass)" />
              <XAxis dataKey="timestamp"
                tickFormatter={v => new Date(v).toLocaleDateString()}
                tick={{fontSize:9, fill:'var(--text-muted)'}} />
              <YAxis domain={[0,1]} tick={{fontSize:9, fill:'var(--text-muted)'}} />
              <Tooltip content={<ChartTooltip/>} />
              <Line type="monotone" dataKey="accuracy" stroke="var(--accent-cyan)"   strokeWidth={2} dot={false} name="Accuracy"/>
              <Line type="monotone" dataKey="f1_score"  stroke="var(--accent-purple)" strokeWidth={2} dot={false} name="F1"/>
            </LineChart>
          </ResponsiveContainer>
          {metrics.some(m => m.drift_detected) && (
            <div className="mt-4 flex items-center gap-2 p-3 rounded-lg"
              style={{background:'color-mix(in srgb, var(--accent-warning) 10%, transparent)', border:'1px solid color-mix(in srgb, var(--accent-warning) 25%, transparent)'}}>
              <AlertTriangle size={12} style={{color:'var(--accent-warning)', flexShrink:0}}/>
              <p className="text-[11px]" style={{color:'var(--accent-warning)'}}>
                Drift detected in recent metrics. Consider retraining.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
