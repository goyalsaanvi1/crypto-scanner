import json
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from scanner.config import ConfigError, parse_config
from scanner.engine import run_all_detectors
from scanner.models import ScanRecord, SessionLocal, save_scan_record
from scanner.report import RULE_DESCRIPTIONS, build_sarif_document

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
SAMPLE_CATEGORIES = ("vulnerable", "safe")

app = FastAPI(title="crypto-scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


class FileInput(BaseModel):
    name: str
    code: str


class ScanRequest(BaseModel):
    code: str | None = None
    files: list[FileInput] | None = None
    rules: dict | None = None


class ConfigParseRequest(BaseModel):
    yaml_text: str


def _findings_payload(findings) -> list[dict]:
    return [
        {
            "line_number": finding.line_number,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "message": finding.message,
        }
        for finding in findings
    ]


def _empty_summary() -> dict:
    return {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def _add_to_summary(summary: dict, findings) -> None:
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/samples")
def list_samples() -> list[dict]:
    samples = []
    for category in SAMPLE_CATEGORIES:
        category_dir = SAMPLES_DIR / category
        if not category_dir.is_dir():
            continue
        for java_file in sorted(category_dir.glob("*.java")):
            relative_path = f"{category}/{java_file.name}"
            samples.append(
                {
                    "name": relative_path,
                    "path": relative_path,
                    "code": java_file.read_text(),
                }
            )
    return samples


@app.get("/api/rules")
def list_rules() -> list[dict]:
    return [{"rule_id": rule_id, "description": description} for rule_id, description in RULE_DESCRIPTIONS]


@app.post("/api/config/parse")
def parse_config_yaml(request: ConfigParseRequest) -> dict:
    try:
        raw = yaml.safe_load(request.yaml_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from exc

    try:
        config = parse_config(raw)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "rules": {
            rule_id: {"enabled": rule_cfg.enabled, "severity_override": rule_cfg.severity_override}
            for rule_id, rule_cfg in config.rules.items()
        }
    }


@app.post("/api/scan")
def scan(request: ScanRequest) -> dict:
    try:
        config = parse_config({"rules": request.rules or {}})
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if request.files is not None:
        overall_summary = _empty_summary()
        file_results = []
        history_findings = []
        for file_input in request.files:
            findings = run_all_detectors(file_input.code, config)
            file_summary = _empty_summary()
            _add_to_summary(file_summary, findings)
            _add_to_summary(overall_summary, findings)
            findings_payload = _findings_payload(findings)
            file_results.append(
                {
                    "name": file_input.name,
                    "findings": findings_payload,
                    "summary": file_summary,
                }
            )
            history_findings.extend(
                {**finding, "file": file_input.name} for finding in findings_payload
            )

        snippet = ", ".join(file_input.name for file_input in request.files)
        save_scan_record(f"{len(request.files)} files: {snippet}", history_findings, overall_summary)

        return {"files": file_results, "summary": overall_summary}

    findings = run_all_detectors(request.code or "", config)
    summary = _empty_summary()
    _add_to_summary(summary, findings)
    findings_payload = _findings_payload(findings)

    save_scan_record(request.code or "", findings_payload, summary)

    return {"findings": findings_payload, "summary": summary}


@app.post("/api/scan/export")
def export_scan(request: ScanRequest, format: str = "json") -> Response:
    if format not in ("json", "sarif"):
        raise HTTPException(status_code=400, detail=f"Unknown export format: {format}")

    try:
        config = parse_config({"rules": request.rules or {}})
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if request.files is not None:
        file_findings = [
            (Path(file_input.name), run_all_detectors(file_input.code, config))
            for file_input in request.files
        ]
    else:
        file_findings = [(Path("input.java"), run_all_detectors(request.code or "", config))]

    if format == "sarif":
        document = build_sarif_document(file_findings)
    else:
        document = [
            {"file": str(path), **finding}
            for path, findings in file_findings
            for finding in _findings_payload(findings)
        ]

    filename = f"crypto-scanner-results.{format}"
    return Response(
        content=json.dumps(document, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/history")
def list_history() -> list[dict]:
    session = SessionLocal()
    try:
        records = (
            session.query(ScanRecord)
            .order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
            .limit(20)
            .all()
        )
        return [
            {
                "id": record.id,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "source_snippet": record.source_snippet,
                "summary": json.loads(record.summary_json),
            }
            for record in records
        ]
    finally:
        session.close()


@app.get("/api/history/{record_id}")
def get_history_record(record_id: int) -> dict:
    session = SessionLocal()
    try:
        record = session.get(ScanRecord, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"No scan record with id {record_id}")
        return {
            "id": record.id,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "source_snippet": record.source_snippet,
            "findings_json": json.loads(record.findings_json),
            "summary_json": json.loads(record.summary_json),
        }
    finally:
        session.close()


@app.delete("/api/history/{record_id}")
def delete_history_record(record_id: int) -> dict:
    session = SessionLocal()
    try:
        record = session.get(ScanRecord, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"No scan record with id {record_id}")
        session.delete(record)
        session.commit()
        return {"deleted": record_id}
    finally:
        session.close()


@app.delete("/api/history")
def clear_history() -> dict:
    session = SessionLocal()
    try:
        deleted = session.query(ScanRecord).delete()
        session.commit()
        return {"deleted": deleted}
    finally:
        session.close()


def main() -> None:
    import uvicorn

    uvicorn.run("scanner.api:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
