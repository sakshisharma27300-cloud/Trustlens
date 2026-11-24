"""
Database Models for Historical Investigations & Threat Intelligence Cache
Uses SQLAlchemy with SQLite/Postgres compatibility.
"""
from datetime import datetime
import json
from sqlalchemy import Column, String, Float, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class InvestigationRecord(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)
    entity = Column(String(512), index=True)
    type = Column(String(32), index=True)
    verdict = Column(String(64), index=True)
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    coverage = Column(Float, default=0.0)
    summary = Column(Text)
    report_json = Column(Text)  # Full serialized report
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "entity": self.entity,
            "type": self.type,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "coverage": self.coverage,
            "summary": self.summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "report": json.loads(self.report_json) if self.report_json else None
        }

# SQLite Synchronous engine for fast and reliable persistence
DB_FILE = "trustlens.db"
engine = create_engine(f"sqlite:///{DB_FILE}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def save_investigation(report_dict: dict) -> None:
    db = SessionLocal()
    try:
        record = InvestigationRecord(
            id=str(report_dict["investigation_id"]),
            entity=str(report_dict["submitted_entity"])[:512],
            type=str(report_dict["investigation_type"]),
            verdict=str(report_dict["overall_verdict"]),
            risk_score=float(report_dict["risk_score"]),
            confidence=float(report_dict["assessment_confidence"]),
            coverage=float(report_dict["analysis_coverage"]),
            summary=str(report_dict["executive_summary"]),
            report_json=json.dumps(report_dict, default=str)
        )
        db.merge(record)
        db.commit()
    finally:
        db.close()

def get_recent_investigations(limit: int = 50):
    db = SessionLocal()
    try:
        records = db.query(InvestigationRecord).order_by(InvestigationRecord.created_at.desc()).limit(limit).all()
        return [r.to_dict() for r in records]
    finally:
        db.close()

def get_investigation_by_id(inv_id: str):
    db = SessionLocal()
    try:
        r = db.query(InvestigationRecord).filter(InvestigationRecord.id == inv_id).first()
        return r.to_dict() if r else None
    finally:
        db.close()

def delete_investigation_by_id(inv_id: str) -> bool:
    db = SessionLocal()
    try:
        r = db.query(InvestigationRecord).filter(InvestigationRecord.id == inv_id).first()
        if r:
            db.delete(r)
            db.commit()
            return True
        return False
    finally:
        db.close()
