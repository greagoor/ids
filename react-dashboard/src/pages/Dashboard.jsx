import React, { useEffect, useState, useRef } from 'react'
import { supabase } from '../lib/supabase'
import { fetchAlerts } from '../lib/api'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid
} from 'recharts'
import { AlertTriangle, Shield, Activity, Lock, Radio } from 'lucide-react'

// ── Theme-aware color helpers ────────────────────────────────────────
const SEV_COLORS  = { CRITICAL:'var(--accent-danger)', HIGH:'var(--accent-warning)', MEDIUM:'#eab308', LOW:'var(--accent-success)' }
const ATK_COLORS  = ['var(--accent-cyan)','var(--accent-purple)','var(--accent-warning)','var(--accent-success)','var(--accent-danger)','#f472b6','#fbbf24']

// ── Sub-components ───────────────────────────────────────────────────
function SeverityBadge({ severity = 'LOW' }) {
  const cls = { CRITICAL:'badge-critical', HIGH:'badge-high', MEDIUM:'badge-medium', LOW:'badge-low' }
  return (
    <span className={`text-[9px] px-2 py-0.5 rounded font-display font-semibold tracking-widest ${cls[severity] || 'badge-info'}`}>
      {severity}
    </span>
  )
}

function KpiCard({ label, value, icon: Icon, color, sub, flash }) {
  const prevRef = useRef(value)
  const [animate, setAnimate] = useState(false)
  useEffect(() => {
    if (prevRef.current !== value) { setAnimate(true); setTimeout(() => setAnimate(false), 600) }
    prevRef.current = value
  }, [value])

  return (
    <div className="hud-card p-6 glow-hover" style={{minHeight:100}}>
      <div className="flex items-start justify-between mb-3">
        <p className="text-[10px] font-display font-medium tracking-widest" style={{color:'var(--text-muted)'}}>
          {label}
        </p>
        <Icon size={15} style={{color, flexShrink:0}}/>
      </div>
      <p className={`text-3xl font-display font-bold transition-all ${animate ? 'scale-110' : 'scale-100'}`}
        style={{color}}>
        {value}
      </p>
      {sub && <p className="text-[10px] mt-1.5" style={{color:'var(--text-muted)'}}>{sub}</p>}
    </div>
  )
}

// Skeleton loader for cards
function SkeletonCard() {
  return (
    <div className="hud-card p-6">
      <div className="skeleton h-3 w-24 mb-4 rounded"/>
      <div className="skeleton h-8 w-16 rounded"/>
    </div>
  )
}

function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-lg" style={{background:'var(--bg-base)'}}>
      <div className="skeleton h-4 w-16 rounded"/>
      <div className="skeleton h-3 w-24 rounded flex-shrink-0"/>
      <div className="skeleton h-3 w-20 rounded flex-shrink-0"/>
      <div className="skeleton h-3 flex-1 rounded"/>
    </div>
  )
}

// Custom chart tooltip
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="glass px-3 py-2 text-xs" style={{minWidth:100}}>
      {label && <p className="font-display text-[10px] tracking-wider mb-1" style={{color:'var(--text-muted)'}}>{label}</p>}
      {payload.map((p,i) => (
        <p key={i} style={{color: p.color || 'var(--accent-cyan)'}}>
          {p.name}: <span className="font-bold">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const [alerts,  setAlerts]  = useState([])
  const [loading, setLoading] = useState(true)
  const [newIds,  setNewIds]  = useState(new Set())
  const feedRef = useRef(null)

  // Initial load — same fetchAlerts call as before
  useEffect(() => {
    fetchAlerts(100).then(r => {
      setAlerts(r.data || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  // Realtime subscription — unchanged from original
  useEffect(() => {
    const channel = supabase
      .channel('alerts-realtime')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'alerts' }, payload => {
        setAlerts(prev => [payload.new, ...prev].slice(0, 200))
        setNewIds(prev => new Set([...prev, payload.new.id]))
        setTimeout(() => setNewIds(prev => { const n = new Set(prev); n.delete(payload.new.id); return n }), 2000)
        if (feedRef.current) feedRef.current.scrollTop = 0
      })
      .subscribe()
    return () => supabase.removeChannel(channel)
  }, [])

  // Derived stats — identical calculation as before
  const totalAlerts     = alerts.length
  const blocked         = alerts.filter(a => a.verdict === 'CRITICAL' || a.verdict === 'HIGH').length
  const avgConf         = alerts.length ? Math.round(alerts.reduce((s,a) => s+(a.confidence||0),0)/alerts.length) : 0
  const activeIncidents = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length

  // Severity distribution — same as before
  const severityData = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => ({
    name: s, value: alerts.filter(a => a.severity === s).length
  })).filter(d => d.value > 0)

  // Attack type distribution — same as before
  const attackCounts = {}
  alerts.forEach(a => { if(a.attack_type) attackCounts[a.attack_type] = (attackCounts[a.attack_type]||0)+1 })
  const attackData = Object.entries(attackCounts)
    .sort((a,b) => b[1]-a[1]).slice(0,7)
    .map(([name,count]) => ({ name: name.replace('_',' '), count }))

  // Suspicion histogram — same as before
  const histogram = Array.from({length:10},(_,i)=>({ range:`${i*10}–${i*10+10}`, count:0 }))
  alerts.forEach(a => {
    const s = a.suspicion_score || 0
    const b = Math.min(Math.floor(s*10),9)
    histogram[b].count++
  })

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">
          Security Operations Center
        </h1>
        <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
          Live threat monitoring · Powered by Agentic AI
        </p>
      </div>

      {/* KPI cards — asymmetric: 4 small + 1 LIVE feed dominant below */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-5">
        {loading ? (
          Array.from({length:4}).map((_,i) => <SkeletonCard key={i}/>)
        ) : (
          <>
            <KpiCard label="TOTAL ALERTS"     value={totalAlerts}     icon={AlertTriangle} color="var(--accent-cyan)"    sub="All time"/>
            <KpiCard label="AVG CONFIDENCE"   value={`${avgConf}%`}   icon={Activity}      color="var(--accent-purple)"  sub="Rule + ML"/>
            <KpiCard label="BLOCKED / HIGH"   value={blocked}          icon={Lock}          color="var(--accent-danger)"  sub="CRITICAL + HIGH"/>
            <KpiCard label="ACTIVE INCIDENTS" value={activeIncidents}  icon={Shield}        color="var(--accent-warning)" sub="HIGH+ severity"/>
          </>
        )}
      </div>

      {/* Charts — asymmetric: bar chart 2/3, donut 1/3 */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Attack type bar — dominant, 2 cols */}
        <div className="hud-card p-6 xl:col-span-2">
          <p className="text-[10px] font-display font-semibold tracking-widest mb-5" style={{color:'var(--text-muted)'}}>
            ATTACK TYPE DISTRIBUTION
          </p>
          {attackData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={attackData} margin={{top:0,right:0,left:-20,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-glass)" />
                <XAxis dataKey="name" tick={{fontSize:10, fill:'var(--text-muted)', fontFamily:'Inter'}} />
                <YAxis tick={{fontSize:10, fill:'var(--text-muted)'}} />
                <Tooltip content={<ChartTooltip/>} />
                <Bar dataKey="count" radius={[4,4,0,0]}>
                  {attackData.map((_,i) => <Cell key={i} fill={ATK_COLORS[i%ATK_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state h-48">
              <Activity size={32}/>
              <p className="font-display text-[10px] tracking-widest">NO ATTACK DATA YET</p>
              <p>Run a simulation from the header to generate traffic</p>
            </div>
          )}
        </div>

        {/* Severity donut — 1 col */}
        <div className="hud-card p-6 flex flex-col">
          <p className="text-[10px] font-display font-semibold tracking-widest mb-4" style={{color:'var(--text-muted)'}}>
            SEVERITY BREAKDOWN
          </p>
          {severityData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityData} dataKey="value" cx="50%" cy="50%" innerRadius={45} outerRadius={72} paddingAngle={3}>
                    {severityData.map((entry,i) => (
                      <Cell key={i} fill={SEV_COLORS[entry.name] || 'var(--text-muted)'} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip/>} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-x-3 gap-y-1.5 mt-3">
                {severityData.map(d => (
                  <div key={d.name} className="flex items-center gap-1.5 text-[10px]" style={{color:'var(--text-secondary)'}}>
                    <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{background: SEV_COLORS[d.name]}} />
                    {d.name} ({d.value})
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state flex-1">
              <Shield size={28}/>
              <p className="font-display text-[10px] tracking-widest">NO DATA</p>
            </div>
          )}
        </div>
      </div>

      {/* Suspicion histogram — full width, shorter */}
      <div className="hud-card p-6">
        <p className="text-[10px] font-display font-semibold tracking-widest mb-4" style={{color:'var(--text-muted)'}}>
          ML SUSPICION SCORE DISTRIBUTION
        </p>
        <ResponsiveContainer width="100%" height={90}>
          <BarChart data={histogram} margin={{top:0,right:0,left:-30,bottom:0}}>
            <XAxis dataKey="range" tick={{fontSize:9, fill:'var(--text-muted)'}} />
            <YAxis tick={{fontSize:9, fill:'var(--text-muted)'}} />
            <Tooltip content={<ChartTooltip/>} />
            <Bar dataKey="count" fill="var(--accent-cyan)" radius={[3,3,0,0]} opacity={0.85} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Live alert feed — DOMINANT: full width, taller */}
      <div className="hud-card p-6">
        <div className="flex items-center gap-3 mb-5">
          <span className="live-dot"/>
          <p className="text-xs font-display font-semibold tracking-widest" style={{color:'var(--accent-cyan)'}}>
            LIVE ALERT FEED
          </p>
          <Radio size={12} style={{color:'var(--accent-cyan)'}} className="animate-pulse-slow"/>
          <span className="ml-auto text-[10px]" style={{color:'var(--text-muted)'}}>
            {alerts.length} total
          </span>
        </div>

        {loading ? (
          <div className="space-y-2">
            {Array.from({length:5}).map((_,i) => <SkeletonRow key={i}/>)}
          </div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <AlertTriangle size={36}/>
            <p className="font-display text-[10px] tracking-widest">NO ALERTS YET</p>
            <p>Run a simulation or wait for live tshark traffic to generate alerts.</p>
          </div>
        ) : (
          <div ref={feedRef} className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
            {alerts.slice(0,50).map((alert, i) => (
              <div
                key={alert.id || i}
                className={`flex items-center gap-3 px-4 py-2.5 rounded-lg text-xs transition-all duration-200 hover:scale-[1.005] ${newIds.has(alert.id) ? 'flash-new' : ''}`}
                style={{
                  background: 'color-mix(in srgb, var(--bg-elevated) 60%, transparent)',
                  border: '1px solid var(--border-glass)',
                }}
              >
                <SeverityBadge severity={alert.severity} />
                <span className="mono font-medium w-28 truncate flex-shrink-0" style={{color:'var(--text-primary)'}}>
                  {alert.ip || alert.src_ip}
                </span>
                <span className={`font-semibold w-28 truncate flex-shrink-0 atk-${(alert.attack_type||'').toLowerCase().replace('_','-').split('_')[0]}`}>
                  {(alert.attack_type||'UNKNOWN').replace('_',' ')}
                </span>
                <span className="flex-1 truncate" style={{color:'var(--text-muted)'}}>
                  {alert.url || alert.uri}
                </span>
                <span className="ml-auto whitespace-nowrap mono" style={{color:'var(--text-muted)', fontSize:'0.68rem'}}>
                  {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
