import json
import os
import tempfile
from pathlib import Path

import pytest

# scanner.models reads CRYPTO_SCANNER_DB_PATH at import time, so this must
# be set before the first `from scanner.api import app` anywhere in the
# test session, pointing history persistence at a throwaway file instead
# of the real data/scan_history.db.
_tmp_db_dir = tempfile.mkdtemp()
os.environ["CRYPTO_SCANNER_DB_PATH"] = str(Path(_tmp_db_dir) / "test_scan_history.db")

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from scanner.api import app  # noqa: E402
from scanner.report import RULE_IDS  # noqa: E402

client = TestClient(app)

SAMPLES_DIR = Path(__file__).parent.parent / "samples"
WEAK_RSA_CODE = (SAMPLES_DIR / "vulnerable" / "WeakRsaKey.java").read_text()
ECB_CODE = (SAMPLES_DIR / "vulnerable" / "EcbExample.java").read_text()


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_samples_returns_vulnerable_and_safe_entries():
    response = client.get("/api/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) > 0
    assert all({"name", "path", "code"} <= set(sample) for sample in samples)
    assert any(sample["path"].startswith("vulnerable/") for sample in samples)
    assert any(sample["path"].startswith("safe/") for sample in samples)


def test_list_rules_matches_rule_catalog():
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = response.json()
    assert {rule["rule_id"] for rule in rules} == set(RULE_IDS)
    assert all(rule["description"] for rule in rules)


def test_scan_single_code_returns_findings_and_summary():
    response = client.post("/api/scan", json={"code": WEAK_RSA_CODE, "rules": {}})
    assert response.status_code == 200
    data = response.json()

    assert data["findings"] == [
        {
            "line_number": 6,
            "rule_id": "WEAK_KEY_SIZE",
            "severity": "MEDIUM",
            "message": data["findings"][0]["message"],
        }
    ]
    assert data["summary"] == {"HIGH": 0, "MEDIUM": 1, "LOW": 0}


def test_scan_empty_code_returns_no_findings():
    response = client.post("/api/scan", json={"code": "", "rules": {}})
    assert response.status_code == 200
    data = response.json()
    assert data["findings"] == []
    assert data["summary"] == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_scan_disabled_rule_produces_no_findings_for_that_rule():
    response = client.post(
        "/api/scan",
        json={"code": WEAK_RSA_CODE, "rules": {"WEAK_KEY_SIZE": {"enabled": False}}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["findings"] == []
    assert data["summary"] == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_scan_severity_override_changes_reported_severity():
    response = client.post(
        "/api/scan",
        json={
            "code": WEAK_RSA_CODE,
            "rules": {"WEAK_KEY_SIZE": {"enabled": True, "severity_override": "HIGH"}},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["summary"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 0}


def test_scan_unknown_rule_id_returns_400():
    response = client.post(
        "/api/scan",
        json={"code": WEAK_RSA_CODE, "rules": {"NOT_A_REAL_RULE": {"enabled": False}}},
    )
    assert response.status_code == 400
    assert "NOT_A_REAL_RULE" in response.json()["detail"]


def test_scan_batch_mode_returns_per_file_and_aggregate_summary():
    response = client.post(
        "/api/scan",
        json={
            "files": [
                {"name": "WeakRsaKey.java", "code": WEAK_RSA_CODE},
                {"name": "EcbExample.java", "code": ECB_CODE},
            ],
            "rules": {},
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert [f["name"] for f in data["files"]] == ["WeakRsaKey.java", "EcbExample.java"]
    assert data["files"][0]["summary"] == {"HIGH": 0, "MEDIUM": 1, "LOW": 0}
    assert data["files"][1]["summary"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert data["summary"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 0}


def test_export_json_single_file():
    response = client.post(
        "/api/scan/export",
        params={"format": "json"},
        json={"code": WEAK_RSA_CODE, "rules": {}},
    )
    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="crypto-scanner-results.json"'
    document = json.loads(response.content)
    assert document == [
        {
            "file": "input.java",
            "line_number": 6,
            "rule_id": "WEAK_KEY_SIZE",
            "severity": "MEDIUM",
            "message": document[0]["message"],
        }
    ]


def test_export_sarif_single_file():
    response = client.post(
        "/api/scan/export",
        params={"format": "sarif"},
        json={"code": WEAK_RSA_CODE, "rules": {}},
    )
    assert response.status_code == 200
    document = json.loads(response.content)
    assert document["version"] == "2.1.0"
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "WEAK_KEY_SIZE"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "input.java"


def test_export_sarif_batch_attributes_findings_to_correct_file():
    response = client.post(
        "/api/scan/export",
        params={"format": "sarif"},
        json={
            "files": [
                {"name": "WeakRsaKey.java", "code": WEAK_RSA_CODE},
                {"name": "EcbExample.java", "code": ECB_CODE},
            ],
            "rules": {},
        },
    )
    assert response.status_code == 200
    document = json.loads(response.content)
    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in document["runs"][0]["results"]
    }
    assert uris == {"WeakRsaKey.java", "EcbExample.java"}


def test_export_unknown_format_returns_400():
    response = client.post(
        "/api/scan/export",
        params={"format": "xml"},
        json={"code": WEAK_RSA_CODE, "rules": {}},
    )
    assert response.status_code == 400


def test_scan_persists_history_record_and_history_endpoints_reflect_it():
    before = client.get("/api/history").json()

    scan_response = client.post("/api/scan", json={"code": WEAK_RSA_CODE, "rules": {}})
    assert scan_response.status_code == 200

    after = client.get("/api/history").json()
    assert len(after) == len(before) + 1

    newest = after[0]
    assert newest["source_snippet"].startswith("import java.security.KeyPairGenerator;")
    assert newest["summary"] == {"HIGH": 0, "MEDIUM": 1, "LOW": 0}
    assert "findings_json" not in newest

    detail_response = client.get(f"/api/history/{newest['id']}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["findings_json"][0]["rule_id"] == "WEAK_KEY_SIZE"
    assert detail["summary_json"] == {"HIGH": 0, "MEDIUM": 1, "LOW": 0}


def test_history_list_is_most_recent_first():
    client.post("/api/scan", json={"code": WEAK_RSA_CODE, "rules": {}})
    client.post("/api/scan", json={"code": ECB_CODE, "rules": {}})

    history = client.get("/api/history").json()
    ids = [record["id"] for record in history]
    assert ids == sorted(ids, reverse=True)


def test_history_batch_scan_records_file_names_in_snippet():
    client.post(
        "/api/scan",
        json={
            "files": [
                {"name": "WeakRsaKey.java", "code": WEAK_RSA_CODE},
                {"name": "EcbExample.java", "code": ECB_CODE},
            ],
            "rules": {},
        },
    )

    newest = client.get("/api/history").json()[0]
    assert "WeakRsaKey.java" in newest["source_snippet"]
    assert "EcbExample.java" in newest["source_snippet"]


def test_history_detail_404_for_unknown_id():
    response = client.get("/api/history/999999")
    assert response.status_code == 404


def test_delete_history_record_removes_it():
    client.post("/api/scan", json={"code": WEAK_RSA_CODE, "rules": {}})
    record_id = client.get("/api/history").json()[0]["id"]

    delete_response = client.delete(f"/api/history/{record_id}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"deleted": record_id}

    assert client.get(f"/api/history/{record_id}").status_code == 404
    assert all(record["id"] != record_id for record in client.get("/api/history").json())


def test_delete_history_record_404_for_unknown_id():
    response = client.delete("/api/history/999999")
    assert response.status_code == 404


def test_clear_history_removes_all_records():
    client.post("/api/scan", json={"code": WEAK_RSA_CODE, "rules": {}})
    client.post("/api/scan", json={"code": ECB_CODE, "rules": {}})
    assert len(client.get("/api/history").json()) > 0

    response = client.delete("/api/history")
    assert response.status_code == 200
    assert response.json()["deleted"] > 0

    assert client.get("/api/history").json() == []


def test_config_parse_returns_only_explicitly_listed_rules():
    response = client.post(
        "/api/config/parse",
        json={
            "yaml_text": """
            rules:
              ECB_MODE:
                enabled: false
              WEAK_HASH:
                enabled: true
                severity_override: HIGH
            """
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "rules": {
            "ECB_MODE": {"enabled": False, "severity_override": None},
            "WEAK_HASH": {"enabled": True, "severity_override": "HIGH"},
        }
    }


def test_config_parse_empty_yaml_returns_empty_rules():
    response = client.post("/api/config/parse", json={"yaml_text": ""})
    assert response.status_code == 200
    assert response.json() == {"rules": {}}


def test_config_parse_invalid_yaml_returns_400():
    response = client.post("/api/config/parse", json={"yaml_text": "rules: [this is not: valid"})
    assert response.status_code == 400


def test_config_parse_unknown_rule_id_returns_400():
    response = client.post(
        "/api/config/parse",
        json={"yaml_text": "rules:\n  NOT_A_REAL_RULE:\n    enabled: false"},
    )
    assert response.status_code == 400
    assert "NOT_A_REAL_RULE" in response.json()["detail"]
