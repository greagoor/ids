import React, { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'
import { fetchAlerts } from '../lib/api'
import { Network } from 'lucide-react'

// These match the CSS variable accent colors semantically
const ATTACK_COLOR = {
  SQL_INJECTION:    '#f87171',
  XSS:              '#fb923c',
  COMMAND_INJECTION:'#a78bfa',
  LFI:              '#34d399',
  RFI:              '#60a5fa',
  SSRF:             '#f472b6',
  PATH_TRAVERSAL:   '#fbbf24',
  UNKNOWN:          '#6b7280',
}

const SEVERITY_RADIUS = { CRITICAL: 22, HIGH: 16, MEDIUM: 11, LOW: 7 }

export default function AttackGraph() {
  const svgRef  = useRef(null)
  const [alerts,  setAlerts]  = useState([])
  const [loading, setLoading] = useState(true)

  // Same fetch as original
  useEffect(() => {
    fetchAlerts(200).then(r => { setAlerts(r.data || []); setLoading(false) })
  }, [])

  // Same D3 graph logic as original — only visual styles updated
  useEffect(() => {
    if (loading || !alerts.length || !svgRef.current) return

    const ipMap = {}
    const links = []

    alerts.forEach(a => {
      const ip  = a.ip || a.src_ip || 'unknown'
      const atk = a.attack_type || 'UNKNOWN'
      const sev = a.severity || 'LOW'
      if (!ipMap[ip]) ipMap[ip] = { id: ip, attacks: {}, maxSeverity: 'LOW', count: 0 }
      ipMap[ip].attacks[atk] = (ipMap[ip].attacks[atk] || 0) + 1
      ipMap[ip].count++
      const sevOrder = ['LOW','MEDIUM','HIGH','CRITICAL']
      if (sevOrder.indexOf(sev) > sevOrder.indexOf(ipMap[ip].maxSeverity)) ipMap[ip].maxSeverity = sev
    })

    const nodes = Object.values(ipMap).map(n => ({
      ...n,
      dominantAttack: Object.entries(n.attacks).sort((a,b)=>b[1]-a[1])[0]?.[0] || 'UNKNOWN',
    }))

    const ipList = Object.keys(ipMap)
    for (let i = 0; i < ipList.length; i++) {
      for (let j = i+1; j < ipList.length; j++) {
        const a = ipMap[ipList[i]], b = ipMap[ipList[j]]
        const sharedAtks = Object.keys(a.attacks).filter(k => k in b.attacks)
        if (sharedAtks.length > 0) links.push({ source: ipList[i], target: ipList[j], attack: sharedAtks[0] })
      }
    }

    const container = svgRef.current.parentElement
    const W = container.clientWidth || 800
    const H = 520

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', W).attr('height', H)

    // Theme-aware background
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light'
    svg.append('rect').attr('width', W).attr('height', H)
      .attr('fill', isDark ? '#05070d' : '#f4f1ea')

    const g = svg.append('g')
    svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', e => g.attr('transform', e.transform)))

    const sim = d3.forceSimulation(nodes)
      .force('link',      d3.forceLink(links).id(d => d.id).distance(130).strength(0.3))
      .force('charge',    d3.forceManyBody().strength(-220))
      .force('center',    d3.forceCenter(W/2, H/2))
      .force('collision', d3.forceCollide(d => (SEVERITY_RADIUS[d.maxSeverity]||8) + 12))

    const link = g.append('g').selectAll('line').data(links).join('line')
      .attr('stroke', d => ATTACK_COLOR[d.attack] || (isDark?'#1e3a5f':'#c5c0b5'))
      .attr('stroke-opacity', 0.35)
      .attr('stroke-width', 1.5)

    const node = g.append('g').selectAll('g').data(nodes).join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e,d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y })
        .on('drag',  (e,d) => { d.fx=e.x; d.fy=e.y })
        .on('end',   (e,d) => { if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null })
      )

    const defs = svg.append('defs')
    const filter = defs.append('filter').attr('id','glow-node')
    filter.append('feGaussianBlur').attr('stdDeviation','3.5').attr('result','blur')
    filter.append('feMerge').selectAll('feMergeNode')
      .data(['blur','SourceGraphic']).join('feMergeNode').attr('in',d=>d)

    node.append('circle')
      .attr('r', d => SEVERITY_RADIUS[d.maxSeverity] || 8)
      .attr('fill', d => ATTACK_COLOR[d.dominantAttack] || '#6b7280')
      .attr('fill-opacity', isDark ? 0.80 : 0.70)
      .attr('stroke', d => ATTACK_COLOR[d.dominantAttack] || '#6b7280')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', 2)
      .attr('filter', isDark ? 'url(#glow-node)' : 'none')

    node.filter(d => d.count > 1).append('text')
      .text(d => d.count)
      .attr('text-anchor','middle').attr('dy','0.35em')
      .attr('font-size', 9).attr('fill', isDark ? '#fff' : '#1c2233')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('pointer-events','none')

    node.append('text')
      .text(d => d.id.length > 15 ? d.id.slice(0,15)+'…' : d.id)
      .attr('text-anchor','middle')
      .attr('dy', d => (SEVERITY_RADIUS[d.maxSeverity]||8) + 14)
      .attr('font-size', 9)
      .attr('fill', isDark ? '#8b95a8' : '#54607a')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('pointer-events','none')

    const tooltip = d3.select('body').append('div')
      .style('position','fixed').style('z-index','9999')
      .style('background', isDark ? 'rgba(15,20,36,0.92)' : 'rgba(255,255,255,0.92)')
      .style('border', `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : 'rgba(28,34,51,0.12)'}`)
      .style('border-radius','8px').style('padding','8px 12px')
      .style('font-size','11px')
      .style('color', isDark ? '#e8edf7' : '#1c2233')
      .style('pointer-events','none').style('opacity',0)
      .style('backdrop-filter','blur(12px)')

    node.on('mouseover', (e,d) => {
      tooltip.transition().duration(150).style('opacity',1)
      tooltip.html(`<b>${d.id}</b><br/>Dominant: ${d.dominantAttack}<br/>Count: ${d.count}<br/>Severity: ${d.maxSeverity}`)
        .style('left',(e.clientX+12)+'px').style('top',(e.clientY-28)+'px')
    }).on('mouseout', () => tooltip.transition().duration(150).style('opacity',0))

    sim.on('tick', () => {
      link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
          .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y)
      node.attr('transform',d=>`translate(${d.x},${d.y})`)
    })

    return () => { sim.stop(); tooltip.remove() }
  }, [alerts, loading])

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">Attack Graph</h1>
        <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
          IP nodes sized by severity · edges colored by shared attack type · drag to explore
        </p>
      </div>

      {/* Legend */}
      <div className="hud-card p-4 flex flex-wrap gap-3 items-center">
        {Object.entries(ATTACK_COLOR).slice(0,7).map(([k,c]) => (
          <div key={k} className="flex items-center gap-1.5 text-[10px]" style={{color:'var(--text-secondary)'}}>
            <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{background:c}}/>
            {k.replace(/_/g,' ')}
          </div>
        ))}
        <div className="ml-auto flex gap-4 text-[10px]" style={{color:'var(--text-muted)'}}>
          <span>Node size = severity</span>
          <span>Edge = shared attack</span>
        </div>
      </div>

      <div className="hud-card overflow-hidden" style={{minHeight:540}}>
        {loading ? (
          <div className="empty-state" style={{height:540}}>
            <Network size={36}/>
            <p className="font-display text-[10px] tracking-widest">LOADING GRAPH DATA</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="empty-state" style={{height:540}}>
            <Network size={40}/>
            <p className="font-display text-[10px] tracking-widest">NO DATA TO VISUALISE</p>
            <p>Fire a simulation to generate alert nodes.</p>
          </div>
        ) : (
          <svg ref={svgRef} style={{display:'block',width:'100%',height:'540px'}}/>
        )}
      </div>
    </div>
  )
}
