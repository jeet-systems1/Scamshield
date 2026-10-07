from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.core.database import get_db
from app.models.scan import ScanResult
from app.models.user import User
from app.schemas.scan import ScanResponse, ThreatSignal, InputType, RiskLevel
from app.api.auth import get_current_user

router = APIRouter(prefix="/history", tags=["history"])


@router.get("/", response_model=List[ScanResponse])
async def get_history(
    limit: int = 20,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the authenticated user's scan history."""
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(min(limit, 100))
        .offset(offset)
    )
    scans = result.scalars().all()

    return [
        ScanResponse(
            scan_id=s.id,
            input_type=InputType(s.input_type),
            input_preview=s.input_preview,
            risk_score=s.risk_score,
            risk_level=RiskLevel(s.risk_level),
            threat_categories=s.threat_categories,
            signals=[ThreatSignal(**sig) for sig in s.signals],
            explanation=s.explanation,
            recommendation=s.recommendation,
            scanned_at=s.scanned_at,
        )
        for s in scans
    ]
