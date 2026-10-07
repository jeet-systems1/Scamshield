# ScamShield AI 🛡️

An AI-powered platform that detects phishing URLs, scam messages, malicious QR codes, and impersonation fraud — and explains threats in plain English.

## Project Structure

```
scamshield/
├── backend/          # FastAPI backend
│   ├── app/
│   │   ├── api/      # Route handlers
│   │   ├── core/     # Config, security
│   │   ├── models/   # DB models
│   │   ├── schemas/  # Pydantic schemas
│   │   ├── services/ # Business logic (scanners, AI)
│   │   └── main.py
│   ├── requirements.txt
│   └── .env.example
└── frontend/         # React frontend
    ├── src/
    │   ├── components/
    │   ├── pages/
    │   └── App.jsx
    └── package.json
```

## Quick Start

### Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # fill in your API keys
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Tech Stack
- **Backend:** FastAPI, PostgreSQL, Redis, Celery
- **AI:** OpenAI GPT-4o-mini, custom heuristics
- **Frontend:** React, Tailwind CSS, shadcn/ui
- **Deployment:** Vercel (frontend), Railway (backend)
