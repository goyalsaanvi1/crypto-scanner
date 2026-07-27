from pathlib import Path

from scanner.detectors.base import Finding


def print_findings(file_path: Path, findings: list[Finding]) -> None:
    for finding in findings:
        print(
            f"{file_path}:{finding.line_number} "
            f"[{finding.rule_id}] {finding.severity} - {finding.message}"
        )
