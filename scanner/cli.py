import sys
from pathlib import Path

import click

from scanner.config import ConfigError, load_config
from scanner.detectors.ecb_mode import EcbModeDetector
from scanner.detectors.hardcoded_keys import HardcodedKeyDetector
from scanner.detectors.insecure_random import InsecureRandomDetector
from scanner.detectors.insecure_trust_manager import InsecureTrustManagerDetector
from scanner.detectors.static_iv import StaticIvDetector
from scanner.detectors.weak_cipher import WeakCipherDetector
from scanner.detectors.weak_hash import WeakHashDetector
from scanner.detectors.weak_kdf import WeakKdfDetector
from scanner.detectors.weak_key_size import WeakKeySizeDetector
from scanner.report import print_findings, print_sarif

# (rule_id, detector) pairs. Order matches the rule catalog in report.py.
DETECTORS = [
    ("HARDCODED_KEY", HardcodedKeyDetector()),
    ("ECB_MODE", EcbModeDetector()),
    ("STATIC_IV", StaticIvDetector()),
    ("WEAK_CIPHER", WeakCipherDetector()),
    ("WEAK_HASH", WeakHashDetector()),
    ("INSECURE_RANDOM", InsecureRandomDetector()),
    ("WEAK_KEY_SIZE", WeakKeySizeDetector()),
    ("INSECURE_TRUST_MANAGER", InsecureTrustManagerDetector()),
    ("WEAK_KDF", WeakKdfDetector()),
]


def find_java_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix == ".java" else []
    return sorted(target.rglob("*.java"))


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Print 'No findings' for scanned files with zero findings.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "sarif"]),
    default="text",
    help="Output format: text (default) or sarif.",
)
def main(path: Path, verbose: bool, output_format: str) -> None:
    """Scan .java files under PATH for cryptographic misuse patterns.

    Looks for a .cryptoscanner.yml config file in the current working
    directory to enable/disable rules or override their severity.

    Exits 0 if no findings were produced, 1 if any findings were found.
    """
    try:
        config = load_config(Path.cwd())
    except ConfigError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    any_findings = False
    file_findings = []
    for java_file in find_java_files(path):
        content = java_file.read_text()
        findings = []
        for rule_id, detector in DETECTORS:
            if not config.is_enabled(rule_id):
                continue

            detector_findings = detector.scan(content)
            override = config.severity_override(rule_id)
            if override:
                for finding in detector_findings:
                    finding.severity = override

            findings.extend(detector_findings)
        if findings:
            any_findings = True

        if output_format == "text":
            print_findings(java_file, findings, verbose=verbose)
        else:
            file_findings.append((java_file, findings))

    if output_format == "sarif":
        print_sarif(file_findings)

    sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
    main()
