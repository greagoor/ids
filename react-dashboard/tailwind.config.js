/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // CSS-variable-driven tokens — all read from the active theme
        cyber: {
          bg:       'var(--bg-base)',
          surface:  'var(--bg-surface)',
          card:     'var(--bg-elevated)',
          border:   'var(--border-glass)',
          accent:   'var(--accent-cyan)',
          accent2:  'var(--accent-purple)',
          danger:   'var(--accent-danger)',
          warn:     'var(--accent-warning)',
          ok:       'var(--accent-success)',
          muted:    'var(--text-muted)',
          text:     'var(--text-primary)',
          secondary:'var(--text-secondary)',
        },
      },
      fontFamily: {
        sans:    ['Inter', 'system-ui', 'sans-serif'],
        display: ['Orbitron', 'sans-serif'],
        mono:    ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow':   'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in':     'slideIn 0.3s ease-out',
        'slide-up':     'slideUp 0.35s ease-out',
        'fade-in':      'fadeIn 0.4s ease-out',
        'glow':         'glow 2s ease-in-out infinite alternate',
        'ticker':       'ticker 60s linear infinite',
        'radar-sweep':  'radarSweep 4s linear infinite',
        'count-up':     'countUp 0.5s ease-out',
        'new-row':      'newRow 1.5s ease-out forwards',
        'skeleton':     'skeleton 1.5s ease-in-out infinite',
      },
      keyframes: {
        slideIn:     { from: { transform: 'translateY(-8px)', opacity: 0 }, to: { transform: 'translateY(0)', opacity: 1 } },
        slideUp:     { from: { transform: 'translateY(12px)', opacity: 0 }, to: { transform: 'translateY(0)', opacity: 1 } },
        fadeIn:      { from: { opacity: 0 }, to: { opacity: 1 } },
        glow:        { from: { boxShadow: '0 0 5px color-mix(in srgb, var(--accent-cyan) 20%, transparent)' }, to: { boxShadow: '0 0 25px color-mix(in srgb, var(--accent-cyan) 55%, transparent)' } },
        ticker:      { from: { transform: 'translateX(0)' }, to: { transform: 'translateX(-50%)' } },
        radarSweep:  { from: { transform: 'rotate(0deg)' }, to: { transform: 'rotate(360deg)' } },
        newRow:      { '0%': { backgroundColor: 'color-mix(in srgb, var(--accent-cyan) 18%, transparent)' }, '100%': { backgroundColor: 'transparent' } },
        skeleton:    { '0%,100%': { opacity: 0.4 }, '50%': { opacity: 0.8 } },
      },
      boxShadow: {
        'cyber':  '0 0 20px rgba(0,212,255,0.15), 0 4px 24px var(--shadow-color)',
        'danger': '0 0 20px color-mix(in srgb, var(--accent-danger) 30%, transparent)',
        'glow':   '0 0 30px color-mix(in srgb, var(--accent-cyan) 30%, transparent)',
        'hud':    'inset 0 1px 0 var(--border-glass)',
      },
    },
  },
  plugins: [],
}
