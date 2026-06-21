import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Incidents from './pages/Incidents'
import AgentTimeline from './pages/AgentTimeline'
import AiPanel from './pages/AiPanel'
import Chatbot from './pages/Chatbot'
import AttackGraph from './pages/AttackGraph'
import MitreMap from './pages/MitreMap'
import HoneypotLogs from './pages/HoneypotLogs'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/"          element={<Dashboard />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/agents"    element={<AgentTimeline />} />
        <Route path="/ai-panel"  element={<AiPanel />} />
        <Route path="/chat"      element={<Chatbot />} />
        <Route path="/graph"     element={<AttackGraph />} />
        <Route path="/mitre"     element={<MitreMap />} />
        <Route path="/honeypot"  element={<HoneypotLogs />} />
      </Route>
    </Routes>
  )
}
