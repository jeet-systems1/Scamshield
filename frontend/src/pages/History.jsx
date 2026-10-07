import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getHistory } from '../api'

const levelColors = {
  LOW:      { text: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30'  },
  MEDIUM:   { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30' },
  HIGH:     { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  CRITICAL: { text: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30'    },
}

export default function History() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    getHistory()
      .then((r) => setScans(r.data))
      .catch(() => setError('Login required to view history.'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-gray-400 animate-pulse">Loading history...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center">
        <div className="text-4xl mb-4">🔒</div>
        <p className="text-gray-400">{error}</p>
        <button
          onClick={() => navigate('/')}
          className="mt-4 px-6 py-2 bg-blue-600 rounded-xl text-white text-sm hover:bg-blue-500 transition-colors"
        >
          Back to Scan
        </button>
      </div>
    )
  }

  if (scans.length === 0) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center">
        <div className="text-4xl mb-4">📋</div>
        <p className="text-gray-400">No scans yet. Start by scanning a URL or message.</p>
        <button
          onClick={() => navigate('/')}
          className="mt-4 px-6 py-2 bg-blue-600 rounded-xl text-white text-sm hover:bg-blue-500 transition-colors"
        >
          Scan Something
        </button>
      </div>
    )
  }

  return (
    <main className="max-w-2xl mx-auto px-4 py-10">
      <h1 className="text-2xl font-bold text-white mb-6">Scan History</h1>
      <div className="space-y-3">
        {scans.map((scan) => {
          const c = levelColors[scan.risk_level] || levelColors.LOW
          return (
            <button
              key={scan.scan_id}
              onClick={() => navigate(`/result/${scan.scan_id}`, { state: scan })}
              className={`w-full text-left bg-gray-900 border ${c.border} rounded-xl p-4 hover:bg-gray-800 transition-colors`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-gray-500 uppercase">
                  {scan.input_type === 'url' ? '🔗' : scan.input_type === 'text' ? '💬' : '📷'} {scan.input_type}
                </span>
                <span className={`text-xs font-bold ${c.text}`}>
                  {scan.risk_level} · {scan.risk_score}/100
                </span>
              </div>
              <p className="text-gray-300 text-sm font-mono truncate">{scan.input_preview}</p>
              <p className="text-gray-500 text-xs mt-1 truncate">{scan.explanation}</p>
            </button>
          )
        })}
      </div>
    </main>
  )
}
