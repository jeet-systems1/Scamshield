import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT token if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export const scanUrl = (url) => api.post('/scan/url', { url })
export const scanText = (text) => api.post('/scan/text', { text })
export const scanQr = (formData) =>
  api.post('/scan/qr', formData, { headers: { 'Content-Type': 'multipart/form-data' } })
export const getScan = (id) => api.get(`/scan/${id}`)
export const getHistory = () => api.get('/history/')
export const login = (email, password) => api.post('/auth/login', { email, password })
export const register = (email, password) => api.post('/auth/register', { email, password })

export default api
