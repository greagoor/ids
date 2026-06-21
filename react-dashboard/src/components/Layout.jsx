import React, { useState, useEffect, useRef } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { simulateAttack } from '../lib/api'
import { useTheme } from '../lib/ThemeContext'
import { supabase } from '../lib/supabase'
import {
  LayoutDashboard, AlertTriangle, GitBranch, Brain,
  MessageSquare, Network, Map, Bug, ChevronDown,
  Zap, Shield, Activity, Sun, Moon, Menu, X,
  Pin, ChevronRight
} from 'lucide-react'

const NAV = [
  { to: '/',          label: 'Dashboard',      icon: LayoutDashboard },
  { to: '/incidents', label: 'Incidents',      icon: AlertTriangle },
  { to: '/agents',    label: 'Agent Timeline', icon: GitBranch },
  { to: '/ai-panel',  label: 'AI Panel',       icon: Brain },
  { to: '/chat',      label: 'Chatbot',        icon: MessageSquare },
  { to: '/graph',     label: 'Attack Graph',   icon: Network },
  { to: '/mitre',     label: 'MITRE Map',      icon: Map },
  { to: '/honeypot',  label: 'Honeypot',       icon: Bug },
]

const ATTACK_TYPES = ['sqli','xss','cmdi','lfi','rfi','ssrf','path_traversal']

// Radar sweep SVG — purely decorative
function RadarSweep() {
  return (
    <div className="relative w-8 h-8 flex-shrink-0">
      <svg viewBox="0 0 32 32" className="w-full h-full">
        <circle cx="16" cy="16" r="14" fill="none" stroke="var(--accent-cyan)" strokeWidth="0.5" opacity="0.3"/>
        <circle cx="16" cy="16" r="9" fill="none" stroke="var(--accent-cyan)" strokeWidth="0.4" opacity="0.2"/>
        <circle cx="16" cy="16" r="4" fill="none" stroke="var(--accent-cyan)" strokeWidth="0.4" opacity="0.2"/>
        <g style={{transformOrigin:'16px 16px', animation:'radarSweep 4s linear infinite'}}>
          <path d="M16 16 L16 2" stroke="var(--accent-cyan)" strokeWidth="1.2" strokeLinecap="round" opacity="0.7"/>
          <path d="M16 16 L16 2" stroke="var(--accent-cyan)" strokeWidth="6" strokeLinecap="round" opacity="0.08"
            style={{filter:'blur(2px)'}}/>
        </g>
        <circle cx="16" cy="16" r="1.5" fill="var(--accent-cyan)" opacity="0.8"/>
      </svg>
    </div>
  )
}

// Theme toggle with sun/moon morph
function ThemeToggle() {
  const { theme, toggleTheme } = useTheme()
  return (
    <button
      onClick={toggleTheme}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      className="reticle w-9 h-9 rounded-lg flex items-center justify-center border transition-all duration-200"
      style={{
        borderColor: 'var(--border-glass)',
        background: 'var(--bg-glass)',
        color: theme === 'dark' ? 'var(--accent-cyan)' : 'var(--accent-warning)',
      }}
    >
      {theme === 'dark'
        ? <Sun size={15} />
        : <Moon size={15} />
      }
    </button>
  )
}

// Uptime counter (purely cosmetic — starts on mount)
function UptimeCounter() {
  const [secs, setSecs] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setSecs(s => s + 1), 1000)
    return () => clearInterval(t)
  }, [])
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  return (
    <span className="mono text-[10px]" style={{color:'var(--text-muted)'}}>
      UP {String(h).padStart(2,'0')}:{String(m).padStart(2,'0')}:{String(s).padStart(2,'0')}
    </span>
  )
}

// Overall threat level derived from existing alerts data
function ThreatLevelBadge({ alerts }) {
  const hasCritical = alerts.some(a => a.severity === 'CRITICAL')
  const hasHigh     = alerts.some(a => a.severity === 'HIGH')
  const level = hasCritical ? 'CRITICAL' : hasHigh ? 'ELEVATED' : alerts.length > 0 ? 'MODERATE' : 'NOMINAL'
  const colors = {
    CRITICAL: { bg: 'color-mix(in srgb, var(--accent-danger) 15%, transparent)', color: 'var(--accent-danger)', dot: 'var(--accent-danger)' },
    ELEVATED: { bg: 'color-mix(in srgb, var(--accent-warning) 15%, transparent)', color: 'var(--accent-warning)', dot: 'var(--accent-warning)' },
    MODERATE: { bg: 'color-mix(in srgb, #eab308 12%, transparent)', color: '#eab308', dot: '#eab308' },
    NOMINAL:  { bg: 'color-mix(in srgb, var(--accent-success) 12%, transparent)', color: 'var(--accent-success)', dot: 'var(--accent-success)' },
  }
  const c = colors[level]
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px] font-display font-semibold tracking-widest"
      style={{ background: c.bg, color: c.color, border: `1px solid color-mix(in srgb, ${c.color} 25%, transparent)` }}>
      <span className="w-1.5 h-1.5 rounded-full animate-pulse-slow" style={{background: c.dot}}/>
      THREAT: {level}
    </div>
  )
}

// Bottom event ticker — reads from existing realtimeEntries prop
function EventTicker({ entries }) {
  if (!entries.length) return null
  const chips = [...entries, ...entries].slice(0, 40)
  return (
    <div className="h-8 border-t flex items-center overflow-hidden flex-shrink-0"
      style={{background:'var(--bg-surface)', borderColor:'var(--border-glass)'}}>
      <div className="px-3 flex-shrink-0 flex items-center gap-1.5 border-r"
        style={{borderColor:'var(--border-glass)'}}>
        <span className="live-dot" style={{width:5,height:5}}/>
        <span className="font-display text-[8px] tracking-widest" style={{color:'var(--accent-cyan)'}}>LIVE</span>
      </div>
      <div className="ticker-wrap flex-1">
        <div className="ticker-inner flex items-center gap-6 px-4">
          {chips.map((e, i) => {
            const actionColor = {
              ALERT_DETECTED: 'var(--accent-warning)',
              BLOCK: 'var(--accent-danger)',
              BLOCK_MOCK: 'var(--accent-danger)',
              INVESTIGATION_COMPLETE: 'var(--accent-purple)',
              HONEYPOT_ROUTED: '#f472b6',
              ROUTE_TO_INVESTIGATION: 'var(--accent-cyan)',
            }[e.action] || 'var(--text-secondary)'
            return (
              <span key={i} className="flex items-center gap-2 text-[10px] whitespace-nowrap">
                <span className="w-1 h-1 rounded-full flex-shrink-0" style={{background: actionColor}}/>
                <span style={{color:'var(--text-secondary)'}}>{e.agent?.replace(/_/g,' ')}</span>
                <span className="font-semibold" style={{color: actionColor}}>{e.action?.replace(/_/g,' ')}</span>
                {e.timestamp && (
                  <span style={{color:'var(--text-muted)'}}>{new Date(e.timestamp).toLocaleTimeString()}</span>
                )}
                <span style={{color:'var(--border-glass)'}}>·</span>
              </span>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default function Layout() {
  const [sidebarExpanded, setSidebarExpanded] = useState(false)
  const [sidebarPinned,   setSidebarPinned]   = useState(false)
  const [simOpen,     setSimOpen]     = useState(false)
  const [simType,     setSimType]     = useState('sqli')
  const [simLoading,  setSimLoading]  = useState(false)
  const [simResult,   setSimResult]   = useState(null)
  const [recentAlerts, setRecentAlerts] = useState([])
  const [tickerEntries, setTickerEntries] = useState([])
  const navigate = useNavigate()
  const { theme } = useTheme()

  // Read recent alerts for threat level — using same supabase client already in app
  useEffect(() => {
    supabase.from('alerts').select('severity').order('timestamp', {ascending:false}).limit(30)
      .then(r => setRecentAlerts(r.data || []))
  }, [])

  // Ticker feeds from audit_log — same table AgentTimeline already subscribes to
  useEffect(() => {
    supabase.from('audit_log').select('agent,action,timestamp').order('timestamp',{ascending:false}).limit(20)
      .then(r => setTickerEntries(r.data || []))
    const ch = supabase.channel('layout-ticker')
      .on('postgres_changes', {event:'INSERT', schema:'public', table:'audit_log'}, payload => {
        setTickerEntries(prev => [payload.new, ...prev].slice(0, 30))
      })
      .subscribe()
    return () => supabase.removeChannel(ch)
  }, [])

  const isExpanded = sidebarExpanded || sidebarPinned

  const runSim = async () => {
    setSimLoading(true)
    setSimResult(null)
    try {
      const res = await simulateAttack(simType)
      setSimResult(res)
    } catch (e) {
      setSimResult({ error: e.message })
    }
    setSimLoading(false)
    setTimeout(() => {
      setSimOpen(false)
      navigate('/agents')
    }, 1500)
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{background:'var(--bg-base)'}}>

      {/* ── Sidebar ─────────────────────────────────────────────── */}
      <aside
        className="sidebar-transition flex-shrink-0 flex flex-col border-r"
        style={{
          width: isExpanded ? '220px' : '56px',
          borderColor: 'var(--border-glass)',
          background: 'var(--bg-glass)',
          backdropFilter: 'blur(16px)',
        }}
        onMouseEnter={() => !sidebarPinned && setSidebarExpanded(true)}
        onMouseLeave={() => !sidebarPinned && setSidebarExpanded(false)}
      >
        {/* Logo row */}
        <div className="h-14 flex items-center gap-3 px-3 border-b flex-shrink-0 overflow-hidden"
          style={{borderColor:'var(--border-glass)'}}>
          <Shield size={20} style={{color:'var(--accent-cyan)', flexShrink:0}}/>
          {isExpanded && (
            <span className="font-display font-bold text-sm gradient-text whitespace-nowrap tracking-wider">
              AEGIS IDS
            </span>
          )}
          {isExpanded && (
            <button
              onClick={() => setSidebarPinned(p => !p)}
              className="ml-auto p-1 rounded transition-colors"
              title={sidebarPinned ? 'Unpin sidebar' : 'Pin sidebar'}
              style={{color: sidebarPinned ? 'var(--accent-cyan)' : 'var(--text-muted)'}}
            >
              <Pin size={12}/>
            </button>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 overflow-hidden">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `reticle flex items-center gap-3 mx-2 mb-0.5 rounded-lg transition-all duration-200
                ${isActive
                  ? 'bg-[color-mix(in_srgb,var(--accent-cyan)_10%,transparent)]'
                  : 'hover:bg-[color-mix(in_srgb,var(--accent-cyan)_5%,transparent)]'}`
              }
              style={({ isActive }) => ({
                padding: '9px 10px',
                borderLeft: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                boxShadow: isActive ? `0 0 12px color-mix(in srgb, var(--accent-cyan) 15%, transparent)` : 'none',
              })}
            >
              <Icon size={15} style={{flexShrink:0}}/>
              {isExpanded && (
                <span className="text-[13px] font-medium whitespace-nowrap overflow-hidden">
                  {label}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Status dot */}
        <div className="px-3 py-3 border-t flex items-center gap-2 flex-shrink-0"
          style={{borderColor:'var(--border-glass)'}}>
          <span className="live-dot" style={{flexShrink:0}}/>
          {isExpanded && (
            <span className="text-[10px] whitespace-nowrap" style={{color:'var(--text-muted)'}}>
              Live monitoring
            </span>
          )}
        </div>
      </aside>

      {/* ── Main column ─────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Command Center Header */}
        <header className="h-14 flex items-center gap-4 px-5 border-b flex-shrink-0"
          style={{
            borderColor: 'var(--border-glass)',
            background: 'var(--bg-glass)',
            backdropFilter: 'blur(16px)',
          }}>

          {/* Radar + brand */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <RadarSweep/>
            <div className="hidden md:flex flex-col">
              <span className="font-display text-[11px] font-semibold tracking-widest" style={{color:'var(--text-secondary)'}}>
                COMMAND CENTER
              </span>
            </div>
          </div>

          <div className="w-px h-6 flex-shrink-0" style={{background:'var(--border-glass)'}}/>

          {/* Threat level — data already fetched above */}
          <ThreatLevelBadge alerts={recentAlerts}/>

          {/* Agent health dot */}
          <div className="hidden sm:flex items-center gap-1.5">
            <span className="live-dot"/>
            <span className="text-[10px] font-display tracking-widest" style={{color:'var(--accent-success)'}}>
              AGENTS ONLINE
            </span>
          </div>

          {/* Uptime */}
          <div className="hidden md:block">
            <UptimeCounter/>
          </div>

          {/* Spacer */}
          <div className="flex-1"/>

          {/* Attack sim */}
          <div className="relative">
            <button
              onClick={() => setSimOpen(v => !v)}
              className="reticle flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
              style={{
                background: 'color-mix(in srgb, var(--accent-purple) 15%, transparent)',
                border: '1px solid color-mix(in srgb, var(--accent-purple) 30%, transparent)',
                color: 'var(--accent-purple)',
              }}
            >
              <Zap size={12}/>
              <span className="hidden sm:inline">Simulate</span>
              <ChevronDown size={10} className={`transition-transform ${simOpen ? 'rotate-180' : ''}`}/>
            </button>

            {simOpen && (
              <>
                <div className="fixed inset-0 z-[998]" onClick={() => setSimOpen(false)} />
                <div className="fixed right-6 top-16 w-64 glass p-4 z-[999] shadow-cyber animate-slide-in">
                  <p className="text-[10px] mb-3 font-display font-semibold tracking-widest"
                  style={{color:'var(--text-muted)'}}>DEMO MODE — FIRE ATTACK</p>
                <select
                  value={simType}
                  onChange={e => setSimType(e.target.value)}
                  className="w-full rounded-lg px-3 py-2 text-xs mb-3 focus:outline-none"
                  style={{
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-glass)',
                    color: 'var(--text-primary)',
                  }}
                >
                  {ATTACK_TYPES.map(t => (
                    <option key={t} value={t}>{t.toUpperCase().replace('_',' ')}</option>
                  ))}
                </select>
                <button
                  onClick={runSim}
                  disabled={simLoading}
                  className="w-full py-2 rounded-lg text-xs font-semibold font-display tracking-wider transition-all disabled:opacity-50"
                  style={{
                    background: 'var(--accent-purple)',
                    color: '#fff',
                  }}
                >
                  {simLoading ? 'FIRING...' : '⚡ FIRE ATTACK'}
                </button>
                {simResult && (
                  <div className={`mt-3 p-2 rounded text-[10px] mono ${simResult.error
                    ? 'text-red-400 bg-red-900/20'
                    : 'text-green-400 bg-green-900/20'}`}>
                    {simResult.error
                      ? `Error: ${simResult.error}`
                      : `✓ ${simResult.attack_type?.toUpperCase()} sent → Agent Timeline`}
                  </div>
                )}
              </div>
              </>
            )}
          </div>

          {/* Theme toggle */}
          <ThemeToggle/>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6 md:p-8 page-enter">
          <Outlet/>
        </main>

        {/* Bottom live ticker */}
        <EventTicker entries={tickerEntries}/>
      </div>
    </div>
  )
}
