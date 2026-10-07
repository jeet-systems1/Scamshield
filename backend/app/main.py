from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import init_db
from app.api import scan, auth, history


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create DB tables
    await init_db()
    yield
    # Shutdown: nothing to clean up for SQLite


app = FastAPI(
    title="ScamShield AI",
    description="AI-powered scam and phishing detection API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(scan.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(history.router, prefix="/api/v1")


@app.get("/", tags=["health"])
async def root():
    return {
        "service": "ScamShield AI",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}
