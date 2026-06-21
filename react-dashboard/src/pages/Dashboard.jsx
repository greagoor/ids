import React, { useEffect, useState, useRef } from 'react'
import { supabase, API_URL } from '../lib/supabase'
import { fetchAlerts, SEVERITY_INT_MAP } from '../lib/api'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, AreaChart, Area, Label
} from 'recharts'
import { AlertTriangle, Shield, Activity, Lock, Radio, Download, FileText, FileJson, FileSpreadsheet } from 'lucide-react'

// ── Theme-aware color helpers ────────────────────────────────────────
const SEV_COLORS  = { CRITICAL:'var(--sev-critical)', HIGH:'var(--sev-high)', MEDIUM:'var(--sev-medium)', LOW:'var(--sev-low)' }
const ATK_COLORS  = ['var(--accent-cyan)','var(--accent-purple)','color-mix(in srgb, var(--accent-cyan) 60%, transparent)','color-mix(in srgb, var(--accent-purple) 60%, transparent)','color-mix(in srgb, var(--accent-cyan) 30%, transparent)','color-mix(in srgb, var(--accent-purple) 30%, transparent)']

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
  const [exportHours, setExportHours] = useState(0)
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

  // Derived stats — map severity integer to string
  const totalAlerts     = alerts.length
  const blocked         = alerts.filter(a => a.verdict === 'CRITICAL' || a.verdict === 'HIGH').length
  const avgConf         = alerts.length ? Math.round(alerts.reduce((s,a) => s+(a.confidence||0),0)/alerts.length) : 0
  const activeIncidents = alerts.filter(a => {
    const sev = SEVERITY_INT_MAP[a.severity] || a.severity
    return sev === 'CRITICAL' || sev === 'HIGH'
  }).length

  // Severity distribution
  const severityData = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => ({
    name: s, value: alerts.filter(a => (SEVERITY_INT_MAP[a.severity] || a.severity) === s).length
  })).filter(d => d.value > 0)

  // Attack type distribution — same as before
  const attackCounts = {}
  alerts.forEach(a => { if(a.attack_type) attackCounts[a.attack_type] = (attackCounts[a.attack_type]||0)+1 })
  const attackData = Object.entries(attackCounts)
    .sort((a,b) => b[1]-a[1]).slice(0,7)
    .map(([name,count]) => ({ name: name.replace('_',' '), count }))

  // Suspicion histogram (ignore nulls, 5 buckets)
  const histogram = [
    { range: '0.0–0.2', count: 0 },
    { range: '0.2–0.4', count: 0 },
    { range: '0.4–0.6', count: 0 },
    { range: '0.6–0.8', count: 0 },
    { range: '0.8–1.0', count: 0 },
  ]
  alerts.forEach(a => {
    if (a.suspicion_score === null || a.suspicion_score === undefined) return
    const s = Math.max(0, Math.min(0.999, a.suspicion_score)) // Clamp 0 to 0.999
    const bucket = Math.floor(s * 5)
    histogram[bucket].count++
  })

  const getFilteredAlerts = () => {
    if (exportHours === 0) return alerts
    const cutoff = new Date(Date.now() - exportHours * 3600 * 1000)
    return alerts.filter(a => new Date(a.timestamp) >= cutoff)
  }

  const exportJson = () => {
    const data = getFilteredAlerts()
    if(!data.length) return
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2))
    const a = document.createElement('a')
    a.href = dataStr
    a.download = "alerts_export.json"
    a.click()
  }

  const exportCsv = () => {
    const data = getFilteredAlerts()
    if(!data.length) return
    const keys = Object.keys(data[0])
    const csvStr = [
      keys.join(','),
      ...data.map(a => keys.map(k => `"${(a[k]||'').toString().replace(/"/g, '""')}"`).join(','))
    ].join('\n')
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(csvStr)
    const a = document.createElement('a')
    a.href = dataStr
    a.download = "alerts_export.csv"
    a.click()
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">
            Security Operations Center
          </h1>
          <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
            Live threat monitoring · Powered by Agentic AI
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select value={exportHours} onChange={(e) => setExportHours(Number(e.target.value))} 
            className="rounded-lg px-2 py-1.5 text-[10px] focus:outline-none"
            style={{background:'var(--bg-elevated)', border:'1px solid var(--border-glass)', color:'var(--text-secondary)'}}>
            <option value={0}>All Time</option>
            <option value={24}>Last 24h</option>
            <option value={168}>Last 7d</option>
          </select>
          <button onClick={exportJson} className="reticle flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-display font-semibold tracking-wider transition-all"
            style={{background:'var(--bg-glass)', border:'1px solid var(--border-glass)', color:'var(--text-secondary)'}}>
            <FileJson size={12}/> JSON
          </button>
          <button onClick={exportCsv} className="reticle flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-display font-semibold tracking-wider transition-all"
            style={{background:'var(--bg-glass)', border:'1px solid var(--border-glass)', color:'var(--text-secondary)'}}>
            <FileSpreadsheet size={12}/> CSV
          </button>
          <a href={`${API_URL}/api/export/pdf`} target="_blank" rel="noreferrer"
            className="reticle flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-display font-semibold tracking-wider transition-all"
            style={{background:'color-mix(in srgb, var(--accent-cyan) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--accent-cyan) 30%, transparent)', color:'var(--accent-cyan)'}}>
            <FileText size={12}/> PDF REPORT
          </a>
        </div>
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
              <BarChart data={attackData} layout="vertical" margin={{top:0,right:30,left:40,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-glass)" horizontal={true} vertical={false} />
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" tick={{fontSize:10, fill:'var(--text-primary)', fontFamily:'Inter'}} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip/>} cursor={{fill: 'var(--bg-glass)'}} />
                <Bar dataKey="count" radius={[0,4,4,0]} barSize={16}>
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
        <div className="hud-card p-6 flex flex-col relative">
          <p className="text-[10px] font-display font-semibold tracking-widest mb-4" style={{color:'var(--text-muted)'}}>
            SEVERITY BREAKDOWN
          </p>
          {severityData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityData} dataKey="value" cx="50%" cy="50%" innerRadius={60} outerRadius={75} paddingAngle={2} stroke="none">
                    {severityData.map((entry,i) => (
                      <Cell key={i} fill={SEV_COLORS[entry.name] || 'var(--text-muted)'} />
                    ))}
                    <Label 
                      value={totalAlerts} 
                      position="center" 
                      fill="var(--text-primary)" 
                      style={{ fontSize: '24px', fontWeight: 'bold', fontFamily: 'Inter' }} 
                    />
                  </Pie>
                  <Tooltip content={<ChartTooltip/>} cursor={{fill: 'transparent'}} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-x-3 gap-y-1.5 mt-3 justify-center">
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
          <AreaChart data={histogram} margin={{top:10,right:0,left:-30,bottom:0}}>
            <defs>
              <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.8} />
                <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-glass)" vertical={false} />
            <XAxis dataKey="range" tick={{fontSize:9, fill:'var(--text-muted)'}} axisLine={false} tickLine={false} />
            <YAxis tick={{fontSize:9, fill:'var(--text-muted)'}} axisLine={false} tickLine={false} />
            <Tooltip content={<ChartTooltip/>} cursor={{stroke: 'var(--accent-cyan)', strokeWidth: 1, strokeDasharray: '3 3'}} />
            <Area type="monotone" dataKey="count" stroke="var(--accent-cyan)" fillOpacity={1} fill="url(#colorCount)" strokeWidth={2} />
          </AreaChart>
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
                <SeverityBadge severity={SEVERITY_INT_MAP[alert.severity] || alert.severity} />
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
