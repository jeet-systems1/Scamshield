from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.core.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)  # nullable = anon scans allowed

    input_type = Column(String, nullable=False)   # url | text | qr
    # Store a hash of the input, never raw content in plaintext for privacy
    input_hash = Column(String, nullable=False)
    # Store sanitized/truncated display version
    input_preview = Column(String, nullable=True)

    risk_score = Column(Integer, nullable=False)   # 0-100
    risk_level = Column(String, nullable=False)    # LOW | MEDIUM | HIGH | CRITICAL

    threat_categories = Column(JSON, default=list)  # ["phishing", "brand_impersonation"]
    signals = Column(JSON, default=list)             # raw detection signals
    explanation = Column(Text, nullable=True)        # AI-generated plain English explanation
    recommendation = Column(Text, nullable=True)     # what the user should do

    scanned_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")
