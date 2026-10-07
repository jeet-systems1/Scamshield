from pydantic import BaseModel, HttpUrl, field_validator
from typing import List, Optional, Any
from datetime import datetime
from enum import Enum


class InputType(str, Enum):
    url = "url"
    text = "text"
    qr = "qr"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Request schemas ──────────────────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://", "ftp://")):
            v = "http://" + v
        if len(v) > 2048:
            raise ValueError("URL too long")
        return v


class TextScanRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Text cannot be empty")
        if len(v) > 5000:
            raise ValueError("Text too long (max 5000 chars)")
        return v


# ── Response schemas ─────────────────────────────────────────────────────────

class ThreatSignal(BaseModel):
    name: str
    value: Any
    weight: int        # contribution to risk score 0-100
    description: str   # human-readable signal description


class ScanResponse(BaseModel):
    scan_id: str
    input_type: InputType
    input_preview: Optional[str]
    risk_score: int
    risk_level: RiskLevel
    threat_categories: List[str]
    signals: List[ThreatSignal]
    explanation: str
    recommendation: str
    scanned_at: datetime

    class Config:
        from_attributes = True


# ── Auth schemas ─────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLogin(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True
