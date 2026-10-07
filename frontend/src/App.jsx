import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import Result from './pages/Result'
import History from './pages/History'
import Navbar from './components/Navbar'

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-950 text-white">
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/result/:scanId" element={<Result />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
