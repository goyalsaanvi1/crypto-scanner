from pathlib import Path

from scanner.detectors.base import Finding


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
