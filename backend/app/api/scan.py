import hashlib
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.schemas.scan import (
    URLScanRequest, TextScanRequest, ScanResponse,
    ThreatSignal, InputType, RiskLevel
)
from app.services.heuristics import (
    analyze_url, analyze_text,
    calculate_risk_score, get_risk_level, get_threat_categories
)
from app.services.virustotal import scan_url_virustotal, virustotal_to_signal
from app.services.ai_explainer import generate_explanation
from app.services.qr_scanner import extract_url_from_qr
from app.models.scan import ScanResult
from app.api.auth import get_current_user_optional

router = APIRouter(prefix="/scan", tags=["scan"])


async def _build_and_save_scan(
    db: AsyncSession,
    input_type: str,
    input_value: str,
    signals: list,
    user_id: Optional[str] = None,
) -> ScanResponse:
    """Core pipeline: signals → score → AI explanation → save → return."""

    risk_score = calculate_risk_score(signals)
    risk_level = get_risk_level(risk_score)
    threat_categories = get_threat_categories(signals)

    # Truncate preview for display (never store full content)
    input_preview = input_value[:120] + "..." if len(input_value) > 120 else input_value

    explanation, recommendation = await generate_explanation(
        input_type=input_type,
        input_preview=input_preview,
        signals=signals,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_categories=threat_categories,
    )

    scan_id = str(uuid.uuid4())
    input_hash = hashlib.sha256(input_value.encode()).hexdigest()

    # Persist to DB
    scan_record = ScanResult(
        id=scan_id,
        user_id=user_id,
        input_type=input_type,
        input_hash=input_hash,
        input_preview=input_preview,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_categories=threat_categories,
        signals=signals,
        explanation=explanation,
        recommendation=recommendation,
    )
    db.add(scan_record)
    await db.commit()

    return ScanResponse(
        scan_id=scan_id,
        input_type=InputType(input_type),
        input_preview=input_preview,
        risk_score=risk_score,
        risk_level=RiskLevel(risk_level),
        threat_categories=threat_categories,
        signals=[ThreatSignal(**s) for s in signals],
        explanation=explanation,
        recommendation=recommendation,
        scanned_at=datetime.utcnow(),
    )


@router.post("/url", response_model=ScanResponse)
async def scan_url(
    request: URLScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_optional),
):
    """Scan a URL for phishing and malicious content."""
    url = request.url

    # Layer 1: Heuristics (fast, always runs)
    signals = analyze_url(url)

    # Layer 2: VirusTotal (async, best-effort)
    vt_result = await scan_url_virustotal(url)
    vt_signal = virustotal_to_signal(vt_result)
    if vt_signal:
        signals.append(vt_signal)

    user_id = current_user.id if current_user else None
    return await _build_and_save_scan(db, "url", url, signals, user_id)


@router.post("/text", response_model=ScanResponse)
async def scan_text(
    request: TextScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_optional),
):
    """Scan an SMS or message for scam patterns."""
    signals = analyze_text(request.text)
    user_id = current_user.id if current_user else None
    return await _build_and_save_scan(db, "text", request.text, signals, user_id)


@router.post("/qr", response_model=ScanResponse)
async def scan_qr(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_optional),
):
    """Upload a QR code image. Extracts the URL and scans it."""
    if file.content_type not in ("image/png", "image/jpeg", "image/jpg", "image/webp"):
        raise HTTPException(status_code=400, detail="Only PNG/JPEG/WebP images are supported.")

    image_bytes = await file.read()
    if len(image_bytes) > 5 * 1024 * 1024:  # 5MB limit
        raise HTTPException(status_code=400, detail="Image too large. Max 5MB.")

    extracted = extract_url_from_qr(image_bytes)
    if not extracted:
        raise HTTPException(status_code=422, detail="No QR code found in the image.")

    # If extracted content is a URL, run URL analysis
    if extracted.startswith(("http://", "https://", "www.")):
        signals = analyze_url(extracted)
        vt_result = await scan_url_virustotal(extracted)
        vt_signal = virustotal_to_signal(vt_result)
        if vt_signal:
            signals.append(vt_signal)
        input_type = "qr"
    else:
        # QR contains plain text — run text analysis
        signals = analyze_text(extracted)
        input_type = "qr"

    user_id = current_user.id if current_user else None
    return await _build_and_save_scan(db, input_type, extracted, signals, user_id)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a previous scan result by ID."""
    result = await db.get(ScanResult, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")

    return ScanResponse(
        scan_id=result.id,
        input_type=InputType(result.input_type),
        input_preview=result.input_preview,
        risk_score=result.risk_score,
        risk_level=RiskLevel(result.risk_level),
        threat_categories=result.threat_categories,
        signals=[ThreatSignal(**s) for s in result.signals],
        explanation=result.explanation,
        recommendation=result.recommendation,
        scanned_at=result.scanned_at,
    )
