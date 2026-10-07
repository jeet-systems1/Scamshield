const config = {
  LOW:      { bg: 'bg-green-500/20',  border: 'border-green-500',  text: 'text-green-400',  label: 'LOW RISK',      emoji: '✅' },
  MEDIUM:   { bg: 'bg-yellow-500/20', border: 'border-yellow-500', text: 'text-yellow-400', label: 'MEDIUM RISK',   emoji: '⚠️' },
  HIGH:     { bg: 'bg-orange-500/20', border: 'border-orange-500', text: 'text-orange-400', label: 'HIGH RISK',     emoji: '🚨' },
  CRITICAL: { bg: 'bg-red-500/20',    border: 'border-red-500',    text: 'text-red-400',    label: 'CRITICAL RISK', emoji: '🔴' },
}

export default function RiskBadge({ level, score }) {
  const c = config[level] || config.LOW
  return (
    <div className={`inline-flex items-center gap-3 px-5 py-3 rounded-2xl border ${c.bg} ${c.border}`}>
      <span className="text-3xl">{c.emoji}</span>
      <div>
        <div className={`text-xs font-semibold tracking-widest ${c.text}`}>{c.label}</div>
        <div className={`text-4xl font-black ${c.text}`}>{score}<span className="text-lg font-normal">/100</span></div>
      </div>
    </div>
  )
}
