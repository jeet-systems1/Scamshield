import { Link } from 'react-router-dom'

export default function Navbar() {
  return (
    <nav className="border-b border-gray-800 bg-gray-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-4xl mx-auto px-4 py-3 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-xl">
          <span className="text-2xl">🛡️</span>
          <span className="text-white">ScamShield</span>
          <span className="text-blue-400">AI</span>
        </Link>
        <div className="flex items-center gap-6 text-sm text-gray-400">
          <Link to="/" className="hover:text-white transition-colors">Scan</Link>
          <Link to="/history" className="hover:text-white transition-colors">History</Link>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="hover:text-white transition-colors"
          >
            API Docs
          </a>
        </div>
      </div>
    </nav>
  )
}
