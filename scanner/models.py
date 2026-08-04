import json
import os
from pathlib import Path

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import func

_env_db_path = os.environ.get("CRYPTO_SCANNER_DB_PATH")
if _env_db_path:
    DB_PATH = Path(_env_db_path)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
else:
    DB_DIR = Path(__file__).resolve().parent.parent / "data"
    DB_DIR.mkdir(exist_ok=True)
    DB_PATH = DB_DIR / "scan_history.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    source_snippet = Column(String, nullable=False)
    findings_json = Column(String, nullable=False)
    summary_json = Column(String, nullable=False)


Base.metadata.create_all(engine)


def save_scan_record(source_snippet: str, findings: list[dict], summary: dict) -> ScanRecord:
    session = SessionLocal()
    try:
        record = ScanRecord(
            source_snippet=source_snippet[:200],
            findings_json=json.dumps(findings),
            summary_json=json.dumps(summary),
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return record
    finally:
        session.close()
