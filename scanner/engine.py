from scanner.config import ScannerConfig
from scanner.detectors.base import Finding
from scanner.detectors.ecb_mode import EcbModeDetector
from scanner.detectors.hardcoded_keys import HardcodedKeyDetector
from scanner.detectors.insecure_random import InsecureRandomDetector
from scanner.detectors.insecure_trust_manager import InsecureTrustManagerDetector
from scanner.detectors.static_iv import StaticIvDetector
from scanner.detectors.weak_cipher import WeakCipherDetector
from scanner.detectors.weak_hash import WeakHashDetector
from scanner.detectors.weak_kdf import WeakKdfDetector
from scanner.detectors.weak_key_size import WeakKeySizeDetector
from scanner.suppression import filter_suppressed_findings

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


def run_all_detectors(file_content: str, config: ScannerConfig | None = None) -> list[Finding]:
    """Runs every enabled detector against file_content, applies config
    severity overrides, and filters out inline-suppressed findings. This
    is the single shared entry point used by the CLI, the FastAPI backend,
    and any other future caller — the actual scanning logic lives here
    exactly once."""
    if config is None:
        config = ScannerConfig()

    findings: list[Finding] = []
    for rule_id, detector in DETECTORS:
        if not config.is_enabled(rule_id):
            continue

        detector_findings = detector.scan(file_content)
        override = config.severity_override(rule_id)
        if override:
            for finding in detector_findings:
                finding.severity = override

        findings.extend(detector_findings)

    return filter_suppressed_findings(file_content, findings)
