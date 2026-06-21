import React, { useState, useRef, useEffect } from 'react'
import { sendChat } from '../lib/api'
import { Send, Bot, User, MessageSquare } from 'lucide-react'

const STARTER_QUESTIONS = [
  'Why was IP flagged for SQL injection?',
  'What are the most common attack types today?',
  'Which IPs have been blocked recently?',
  'Explain the MITRE T1190 technique.',
  'What is the current threat level?',
]

function Message({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div className={`flex gap-3 animate-slide-in ${isUser ? 'flex-row-reverse' : ''}`}>
      <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
        style={{
          background: isUser
            ? 'color-mix(in srgb, var(--accent-purple) 20%, transparent)'
            : 'color-mix(in srgb, var(--accent-cyan) 15%, transparent)',
          border: `1px solid ${isUser
            ? 'color-mix(in srgb, var(--accent-purple) 30%, transparent)'
            : 'color-mix(in srgb, var(--accent-cyan) 25%, transparent)'}`,
        }}>
        {isUser
          ? <User size={13} style={{color:'var(--accent-purple)'}}/>
          : <Bot  size={13} style={{color:'var(--accent-cyan)'}}/>
        }
      </div>
      <div className={`max-w-[80%] flex flex-col gap-1 ${isUser ? 'items-end' : 'items-start'}`}>
        <div
          className={`px-4 py-3 text-sm leading-relaxed ${isUser ? 'rounded-2xl rounded-tr-sm' : 'rounded-2xl rounded-tl-sm'}`}
          style={{
            background: isUser
              ? 'color-mix(in srgb, var(--accent-purple) 12%, var(--bg-elevated))'
              : 'var(--bg-glass)',
            border: '1px solid var(--border-glass)',
            backdropFilter: 'blur(12px)',
            color: 'var(--text-primary)',
          }}
        >
          {msg.content}
        </div>
        {msg.sources?.length > 0 && (
          <div className="flex flex-wrap gap-1 px-1">
            {msg.sources.map((s,i) => (
              <span key={i} className="text-[9px] px-1.5 py-0.5 rounded font-mono"
                style={{background:'var(--bg-elevated)', border:'1px solid var(--border-glass)', color:'var(--text-muted)'}}>
                {s}
              </span>
            ))}
          </div>
        )}
        {msg.grounded === false && (
          <p className="text-[9px] px-1" style={{color:'var(--accent-warning)'}}>
            ⚠ No relevant context found in knowledge base
          </p>
        )}
      </div>
    </div>
  )
}

export default function Chatbot() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "Hello! I'm your SOC AI assistant. Ask me anything about alerts, incidents, or threat intelligence. I only use data from the live knowledge base — no hallucinations.",
      sources: []
    }
  ])
  const [input,   setInput]   = useState('')
  const [role,    setRole]    = useState('junior')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Same send logic as original
  const send = async (query) => {
    if (!query.trim() || loading) return
    const userMsg = { role: 'user', content: query }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await sendChat({ query, analystRole: role })
      setMessages(prev => [...prev, {
        role:     'assistant',
        content:  res.answer || 'No response received.',
        sources:  res.sources || [],
        grounded: res.grounded,
      }])
    } catch (e) {
      setMessages(prev => [...prev, {
        role:    'assistant',
        content: `Error: ${e.message}. Is the backend running on port 8000?`,
        sources: [],
      }])
    }
    setLoading(false)
  }

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input) }
  }

  return (
    <div className="flex flex-col h-[calc(100vh-10rem)] animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-2xl font-display font-bold gradient-text tracking-wider">SOC AI Chatbot</h1>
          <p className="text-xs mt-1.5" style={{color:'var(--text-muted)'}}>
            Grounded on live Supabase knowledge base · No hallucinations
          </p>
        </div>
        {/* Role toggle */}
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg"
          style={{background:'var(--bg-glass)', border:'1px solid var(--border-glass)'}}>
          <span className="text-[10px] font-display tracking-widest" style={{color:'var(--text-muted)'}}>ROLE:</span>
          {['junior','senior'].map(r => (
            <button
              key={r}
              onClick={() => setRole(r)}
              className="text-[10px] px-3 py-1 rounded font-display font-semibold tracking-wider transition-all"
              style={{
                background: role === r
                  ? 'color-mix(in srgb, var(--accent-cyan) 12%, transparent)'
                  : 'transparent',
                color: role === r ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: `1px solid ${role === r
                  ? 'color-mix(in srgb, var(--accent-cyan) 25%, transparent)'
                  : 'transparent'}`,
              }}
            >
              {r.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Starter question chips */}
      {messages.length <= 1 && (
        <div className="flex flex-wrap gap-2 mb-5">
          {STARTER_QUESTIONS.map((q,i) => (
            <button
              key={i}
              onClick={() => send(q)}
              className="reticle text-[11px] px-3 py-1.5 rounded-full transition-all hover:scale-[1.02]"
              style={{
                background: 'var(--bg-glass)',
                border: '1px solid var(--border-glass)',
                color: 'var(--text-secondary)',
                backdropFilter: 'blur(10px)',
              }}
            >
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1 mb-4">
        {messages.map((m,i) => <Message key={i} msg={m}/>)}

        {/* Typing indicator */}
        {loading && (
          <div className="flex gap-3 animate-slide-in">
            <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
              style={{
                background: 'color-mix(in srgb, var(--accent-cyan) 15%, transparent)',
                border: '1px solid color-mix(in srgb, var(--accent-cyan) 25%, transparent)',
              }}>
              <Bot size={13} style={{color:'var(--accent-cyan)'}} className="animate-pulse-slow"/>
            </div>
            <div className="px-4 py-3 rounded-2xl rounded-tl-sm"
              style={{background:'var(--bg-glass)', border:'1px solid var(--border-glass)'}}>
              <div className="flex gap-1.5 items-center h-4">
                {[0,1,2].map(i => (
                  <div key={i} className="w-1.5 h-1.5 rounded-full animate-bounce"
                    style={{background:'var(--accent-cyan)', animationDelay:`${i*0.15}s`}}/>
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef}/>
      </div>

      {/* Input bar */}
      <div className="hud-card p-3 flex gap-3 items-end">
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask about alerts, IPs, attack patterns..."
          rows={2}
          className="flex-1 text-sm resize-none focus:outline-none leading-relaxed"
          style={{
            background: 'transparent',
            color: 'var(--text-primary)',
          }}
        />
        <button
          onClick={() => send(input)}
          disabled={!input.trim() || loading}
          className="reticle w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 transition-all hover:scale-105 disabled:opacity-30 disabled:cursor-not-allowed"
          style={{
            background: 'color-mix(in srgb, var(--accent-cyan) 15%, transparent)',
            border: '1px solid color-mix(in srgb, var(--accent-cyan) 30%, transparent)',
            color: 'var(--accent-cyan)',
          }}
        >
          <Send size={13}/>
        </button>
      </div>
    </div>
  )
}
