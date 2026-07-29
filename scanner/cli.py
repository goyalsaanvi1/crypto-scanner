from pathlib import Path

import click

from scanner.detectors.ecb_mode import EcbModeDetector
from scanner.detectors.hardcoded_keys import HardcodedKeyDetector
from scanner.detectors.insecure_random import InsecureRandomDetector
from scanner.detectors.static_iv import StaticIvDetector
from scanner.detectors.weak_cipher import WeakCipherDetector
from scanner.detectors.weak_hash import WeakHashDetector
from scanner.report import print_findings

DETECTORS = [
    HardcodedKeyDetector(),
    EcbModeDetector(),
    StaticIvDetector(),
    WeakCipherDetector(),
    InsecureRandomDetector(),
    WeakHashDetector(),
]


def find_java_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix == ".java" else []
    return sorted(target.rglob("*.java"))


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def main(path: Path) -> None:
    """Scan .java files under PATH for cryptographic misuse patterns."""
    for java_file in find_java_files(path):
        content = java_file.read_text()
        findings = []
        for detector in DETECTORS:
            findings.extend(detector.scan(content))
        print_findings(java_file, findings)


if __name__ == "__main__":
    main()
