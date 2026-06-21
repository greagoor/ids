import React, { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'
import { fetchIncidents } from '../lib/api'
import { Map } from 'lucide-react'

const ALL_TECHNIQUES = ['T1190','T1059','T1059.007','T1083','T1006','T1105','T1090']

const TECHNIQUE_REF = [
  ['T1190',     'Exploit Public-Facing Application', 'SQL_INJECTION'],
  ['T1059.007', 'JavaScript (Scripting Interpreter)', 'XSS'],
  ['T1059',     'Command & Scripting Interpreter',    'COMMAND_INJECTION'],
  ['T1083',     'File and Directory Discovery',       'LFI / PATH_TRAVERSAL'],
  ['T1006',     'Direct Volume Access',               'PATH_TRAVERSAL'],
  ['T1105',     'Ingress Tool Transfer',              'RFI'],
  ['T1090',     'Proxy / Connection Proxy',           'SSRF'],
]

export default function MitreMap() {
  const svgRef    = useRef(null)
  const [counts,  setCounts]  = useState({})
  const [loading, setLoading] = useState(true)

  // Same fetch as original
  useEffect(() => {
    fetchIncidents().then(r => {
      const rows = r.data || []
      const c = {}
      rows.forEach(inc => {
        const tags = inc.mitre_tags || []
        tags.forEach(t => {
          const id = typeof t === 'object' ? t.technique_id : t
          if (id) c[id] = (c[id] || 0) + (inc.count || 1)
        })
      })
      setCounts(c)
      setLoading(false)
    })
  }, [])

  // Same D3 bar chart logic — only colors updated to theme tokens
  useEffect(() => {
    if (loading || !svgRef.current) return

    const techniques = ALL_TECHNIQUES.map(id => ({ id, count: counts[id] || 0 }))
    const maxCount   = Math.max(1, ...techniques.map(t => t.count))
    const isDark     = document.documentElement.getAttribute('data-theme') !== 'light'

    const W   = 640
    const H   = 200
    const pad = 12
    const bW  = (W - pad * (techniques.length + 1)) / techniques.length
    const bH  = 120
    const topY = H - bH - 50

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('viewBox', `0 0 ${W} ${H}`).attr('width','100%')

    svg.append('rect').attr('width',W).attr('height',H)
      .attr('fill', isDark ? '#05070d' : '#f4f1ea')

    const colorScale = d3.scaleSequential(
      d3.interpolateRgb(isDark ? '#1e3a5f' : '#b8d4d8', isDark ? '#00f0ff' : '#0d7d8c')
    ).domain([0, maxCount])

    const tooltip = d3.select('body').append('div')
      .style('position','fixed').style('z-index','9999')
      .style('background', isDark ? 'rgba(15,20,36,0.92)' : 'rgba(255,255,255,0.92)')
      .style('border', `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : 'rgba(28,34,51,0.12)'}`)
      .style('border-radius','8px').style('padding','6px 10px')
      .style('font-size','11px').style('color', isDark ? '#e8edf7' : '#1c2233')
      .style('pointer-events','none').style('opacity',0)
      .style('backdrop-filter','blur(12px)')

    techniques.forEach((t, i) => {
      const x    = pad + i * (bW + pad)
      const barH = t.count > 0 ? (t.count / maxCount) * bH : 4
      const y    = topY + (bH - barH)
      const fill = t.count > 0 ? colorScale(t.count) : (isDark ? '#1e3a5f' : '#d4cfc4')

      const g = svg.append('g').attr('cursor','pointer')
      g.append('rect')
        .attr('x', x).attr('y', y).attr('width', bW).attr('height', barH)
        .attr('fill', fill).attr('rx', 4).attr('opacity', t.count > 0 ? 0.9 : 0.3)
        .on('mouseover', (e) => {
          tooltip.transition().duration(100).style('opacity', 1)
          tooltip.html(`<b>${t.id}</b><br/>Triggered: ${t.count} time${t.count !== 1 ? 's' : ''}`)
            .style('left', (e.clientX+12)+'px').style('top', (e.clientY-28)+'px')
        })
        .on('mouseout', () => tooltip.transition().duration(100).style('opacity', 0))

      if (t.count > 0) {
        g.append('text').text(t.count)
          .attr('x', x + bW/2).attr('y', y - 5)
          .attr('text-anchor','middle').attr('font-size',10)
          .attr('fill', isDark ? '#e8edf7' : '#1c2233')
          .attr('font-family','JetBrains Mono, monospace')
      }

      g.append('text').text(t.id)
        .attr('x', x + bW/2).attr('y', topY + bH + 16)
        .attr('text-anchor','middle').attr('font-size', 9)
        .attr('fill', t.count > 0 ? (isDark?'#8b95a8':'#54607a') : (isDark?'#374151':'#c0b8a4'))
        .attr('font-family','JetBrains Mono, monospace')
    })

    return () => tooltip.remove()
  }, [counts, loading])

  const total = Object.values(counts).reduce((s,v) => s + v, 0)

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">MITRE ATT&CK Map</h1>
        <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
          Technique frequency from observed incidents · hover for detail
        </p>
      </div>

      {/* Summary chips */}
      <div className="flex flex-wrap gap-2 items-center">
        {ALL_TECHNIQUES.map(id => (
          <div key={id}
            className="hud-card px-3 py-2 flex items-center gap-2 text-xs transition-all"
            style={{opacity: counts[id] ? 1 : 0.45}}>
            <span className="mono font-semibold" style={{color:'var(--accent-cyan)'}}>{id}</span>
            <span style={{color: counts[id] ? 'var(--text-secondary)' : 'var(--text-muted)'}}>
              ×{counts[id] || 0}
            </span>
          </div>
        ))}
        <div className="ml-auto hud-card px-3 py-2 text-xs">
          <span style={{color:'var(--text-muted)'}}>Total: </span>
          <span className="font-display font-bold" style={{color:'var(--accent-cyan)'}}>{total}</span>
        </div>
      </div>

      {/* Heatmap chart */}
      <div className="hud-card p-6">
        <p className="text-[10px] font-display font-semibold tracking-widest mb-5" style={{color:'var(--text-muted)'}}>
          TECHNIQUE HIT FREQUENCY
        </p>
        {loading ? (
          <div className="space-y-3">
            <div className="skeleton h-32 w-full rounded"/>
            <div className="flex justify-between gap-2">
              {Array.from({length:7}).map((_,i)=><div key={i} className="skeleton h-3 flex-1 rounded"/>)}
            </div>
          </div>
        ) : total === 0 ? (
          <div className="empty-state">
            <Map size={36}/>
            <p className="font-display text-[10px] tracking-widest">NO MITRE TAGS RECORDED</p>
            <p>Incidents with tagged techniques will appear here once the investigation agent runs.</p>
          </div>
        ) : (
          <svg ref={svgRef} style={{display:'block', width:'100%'}}/>
        )}
      </div>

      {/* Technique reference table */}
      <div className="hud-card p-6">
        <p className="text-[10px] font-display font-semibold tracking-widest mb-4" style={{color:'var(--text-muted)'}}>
          TECHNIQUE REFERENCE
        </p>
        <div className="space-y-1">
          {TECHNIQUE_REF.map(([id, name, maps]) => (
            <div key={id}
              className="reticle flex items-center gap-3 text-xs px-3 py-2.5 rounded-lg transition-colors"
              style={{borderRadius:8}}
              onMouseEnter={e => e.currentTarget.style.background='color-mix(in srgb, var(--accent-cyan) 4%, transparent)'}
              onMouseLeave={e => e.currentTarget.style.background='transparent'}>
              <span className="mono font-semibold w-24 flex-shrink-0" style={{color:'var(--accent-cyan)'}}>
                {id}
              </span>
              <span className="flex-1" style={{color:'var(--text-secondary)'}}>
                {name}
              </span>
              <span className="text-[9px] font-display" style={{color:'var(--accent-purple)'}}>
                {maps}
              </span>
              <span className="text-right w-10 font-display font-bold"
                style={{color: counts[id] ? 'var(--accent-cyan)' : 'var(--text-muted)'}}>
                {counts[id] || 0}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
