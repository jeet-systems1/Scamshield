import { useParams, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { getScan } from '../api'
import RiskBadge from '../components/RiskBadge'

const levelColors = {
  LOW:      'text-green-400',
  MEDIUM:   'text-yellow-400',
  HIGH:     'text-orange-400',
  CRITICAL: 'text-red-400',
}

export default function Result() {
  const { scanId } = useParams()
  const { state } = useLocation()
  const navigate = useNavigate()
  const [data, setData] = useState(state || null)
  const [loading, setLoading] = useState(!state)

  useEffect(() => {
    if (!state) {
      getScan(scanId)
        .then((r) => setData(r.data))
        .catch(() => navigate('/'))
        .finally(() => setLoading(false))
    }
  }, [scanId])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-gray-400 animate-pulse text-lg">Analyzing...</div>
      </div>
    )
  }

  if (!data) return null

  const isHighRisk = ['HIGH', 'CRITICAL'].includes(data.risk_level)

  return (
    <main className="max-w-2xl mx-auto px-4 py-10">
      {/* Back */}
      <button
        onClick={() => navigate('/')}
        className="text-gray-500 hover:text-white text-sm mb-6 flex items-center gap-1 transition-colors"
      >
        ← Scan another
      </button>

      {/* Risk Score */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-4">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-widest mb-2">
              {data.input_type === 'url' ? '🔗 URL Scan' : data.input_type === 'text' ? '💬 Message Scan' : '📷 QR Code Scan'}
            </div>
            <div className="text-gray-400 text-sm font-mono break-all max-w-sm">
              {data.input_preview}
            </div>
          </div>
          <RiskBadge level={data.risk_level} score={data.risk_score} />
        </div>
      </div>

      {/* AI Explanation — the hero section */}
      <div className={`rounded-2xl p-6 mb-4 border ${
        isHighRisk
          ? 'bg-red-500/10 border-red-500/40'
          : 'bg-gray-900 border-gray-800'
      }`}>
        <div className="text-xs text-gray-500 uppercase tracking-widest mb-3">What ScamShield Found</div>
        <p className="text-white text-lg leading-relaxed font-medium">
          {data.explanation}
        </p>
      </div>

      {/* Recommendation */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-2xl p-5 mb-4">
        <div className="text-xs text-blue-400 uppercase tracking-widest mb-2">What You Should Do</div>
        <p className="text-white leading-relaxed">{data.recommendation}</p>
      </div>

      {/* Threat Categories */}
      {data.threat_categories?.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 mb-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-3">Threat Types Detected</div>
          <div className="flex flex-wrap gap-2">
            {data.threat_categories.map((cat) => (
              <span
                key={cat}
                className="px-3 py-1 bg-gray-800 border border-gray-700 rounded-full text-sm text-gray-300"
              >
                {cat}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Signals breakdown */}
      {data.signals?.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 mb-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-3">
            Detection Signals ({data.signals.length})
          </div>
          <div className="space-y-3">
            {data.signals.map((sig, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${
                  sig.weight >= 35 ? 'bg-red-500' : sig.weight >= 20 ? 'bg-yellow-500' : 'bg-blue-500'
                }`} />
                <p className="text-gray-300 text-sm leading-relaxed">{sig.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No signals = clean */}
      {data.signals?.length === 0 && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-5 text-center">
          <div className="text-3xl mb-2">✅</div>
          <p className="text-green-400 font-medium">No threats detected</p>
          <p className="text-gray-400 text-sm mt-1">This content appears to be safe.</p>
        </div>
      )}

      {/* Scan ID */}
      <div className="text-center text-gray-700 text-xs mt-6">
        Scan ID: {data.scan_id}
      </div>
    </main>
  )
}
