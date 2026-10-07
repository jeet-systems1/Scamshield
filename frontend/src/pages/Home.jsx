import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { scanUrl, scanText, scanQr } from '../api'

const TABS = [
  { id: 'url',  label: '🔗 URL',     placeholder: 'Paste a suspicious link here...' },
  { id: 'text', label: '💬 Message', placeholder: 'Paste a suspicious SMS or message here...' },
  { id: 'qr',   label: '📷 QR Code', placeholder: null },
]

export default function Home() {
  const [tab, setTab] = useState('url')
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef()
  const navigate = useNavigate()

  const handleScan = async () => {
    setError('')
    if (!input.trim() && tab !== 'qr') {
      setError('Please enter something to scan.')
      return
    }
    setLoading(true)
    try {
      let res
      if (tab === 'url')  res = await scanUrl(input.trim())
      if (tab === 'text') res = await scanText(input.trim())
      navigate(`/result/${res.data.scan_id}`, { state: res.data })
    } catch (e) {
      setError(e.response?.data?.detail || 'Scan failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleFile = async (file) => {
    if (!file) return
    setError('')
    setLoading(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await scanQr(fd)
      navigate(`/result/${res.data.scan_id}`, { state: res.data })
    } catch (e) {
      setError(e.response?.data?.detail || 'Could not read QR code. Try a clearer image.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="max-w-2xl mx-auto px-4 py-16">
      {/* Hero */}
      <div className="text-center mb-12">
        <div className="text-6xl mb-4">🛡️</div>
        <h1 className="text-4xl font-black text-white mb-3">
          Is this a scam?
        </h1>
        <p className="text-gray-400 text-lg">
          Paste a link, message, or upload a QR code. Get an instant AI-powered answer in plain English.
        </p>
      </div>

      {/* Scan Card */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
        {/* Tabs */}
        <div className="flex gap-2 mb-5">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => { setTab(t.id); setInput(''); setError('') }}
              className={`flex-1 py-2 px-3 rounded-xl text-sm font-medium transition-all ${
                tab === t.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-white'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Input area */}
        {tab !== 'qr' ? (
          <textarea
            className="w-full bg-gray-800 border border-gray-700 rounded-xl p-4 text-white placeholder-gray-500 resize-none focus:outline-none focus:border-blue-500 transition-colors text-sm leading-relaxed"
            rows={4}
            placeholder={TABS.find(t => t.id === tab)?.placeholder}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && e.ctrlKey) handleScan() }}
          />
        ) : (
          <div
            className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
              dragOver ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 hover:border-gray-500'
            }`}
            onClick={() => fileRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]) }}
          >
            <div className="text-4xl mb-2">📷</div>
            <p className="text-gray-400 text-sm">Drop a QR code image here, or click to upload</p>
            <p className="text-gray-600 text-xs mt-1">PNG, JPEG, WebP — max 5MB</p>
            <input
              ref={fileRef}
              type="file"
              accept="image/png,image/jpeg,image/webp"
              className="hidden"
              onChange={(e) => handleFile(e.target.files[0])}
            />
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="mt-3 text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2">
            {error}
          </div>
        )}

        {/* Scan button */}
        {tab !== 'qr' && (
          <button
            onClick={handleScan}
            disabled={loading}
            className="mt-4 w-full py-3 rounded-xl font-bold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all text-base"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                </svg>
                Analyzing...
              </span>
            ) : '🔍 Scan Now'}
          </button>
        )}
      </div>

      {/* Example threats */}
      <div className="mt-8 grid grid-cols-3 gap-3 text-center text-xs text-gray-500">
        {[
          ['🎣', 'Phishing URLs'],
          ['📱', 'Scam SMS'],
          ['📷', 'Malicious QR'],
        ].map(([icon, label]) => (
          <div key={label} className="bg-gray-900/50 border border-gray-800 rounded-xl py-3">
            <div className="text-2xl mb-1">{icon}</div>
            {label}
          </div>
        ))}
      </div>
    </main>
  )
}
