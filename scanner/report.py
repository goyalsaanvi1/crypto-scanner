import json
from pathlib import Path

from scanner.detectors.base import Finding

_SEVERITY_TO_SARIF_LEVEL = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# Every rule_id currently in use, with a short human-readable description
# of what it checks for. Order matches the detector registration order in
# cli.py.
_RULE_DESCRIPTIONS = [
    ("HARDCODED_KEY", "String/byte[] field named like a secret assigned directly to a literal value"),
    ("ECB_MODE", "Cipher.getInstance(...) using ECB mode"),
    ("STATIC_IV", "Hardcoded IV/nonce byte array literal used to build a cipher parameter spec"),
    ("WEAK_CIPHER", "Cipher.getInstance(...) using a weak/deprecated algorithm (DES, DESede, RC4, or Blowfish)"),
    ("WEAK_HASH", "MessageDigest.getInstance(...) using MD5 or SHA-1"),
    ("INSECURE_RANDOM", "java.util.Random used for security-sensitive randomness instead of SecureRandom"),
    ("WEAK_KEY_SIZE", "Key generation with a key size below modern safe thresholds (RSA/EC/AES)"),
    ("INSECURE_TRUST_MANAGER", "TLS certificate or hostname validation disabled or bypassed"),
    ("WEAK_KDF", "PBEKeySpec with a low iteration count and/or a hardcoded salt"),
]

_TOOL_NAME = "crypto-scanner"
_TOOL_INFORMATION_URI = "https://github.com/goyalsaanvi1/crypto-scanner"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)


def print_findings(file_path: Path, findings: list[Finding], verbose: bool = False) -> None:
    if not findings:
        if verbose:
            print(f"{file_path}: No findings")
        return

    for finding in findings:
        print(
            f"{file_path}:{finding.line_number} "
            f"[{finding.rule_id}] {finding.severity} - {finding.message}"
        )


def build_sarif_document(file_findings: list[tuple[Path, list[Finding]]]) -> dict:
    rules = [
        {"id": rule_id, "shortDescription": {"text": description}}
        for rule_id, description in _RULE_DESCRIPTIONS
    ]

    results = []
    for file_path, findings in file_findings:
        uri = Path(file_path).as_posix()
        for finding in findings:
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": finding.line_number},
                            }
                        }
                    ],
                }
            )

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def print_sarif(file_findings: list[tuple[Path, list[Finding]]]) -> None:
    print(json.dumps(build_sarif_document(file_findings), indent=2))
