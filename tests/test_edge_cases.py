"""Confirms the documented known limitations (README "Known Limitations")
actually behave as documented — these are expected misses, not silent
bugs. If a fix ever narrows one of these gaps, the corresponding
assertion below should be updated (and the README limitation reworded)
rather than deleted.
"""

from pathlib import Path

from scanner.detectors.ecb_mode import EcbModeDetector
from scanner.detectors.hardcoded_keys import HardcodedKeyDetector
from scanner.detectors.weak_cipher import WeakCipherDetector
from scanner.detectors.weak_kdf import WeakKdfDetector
from scanner.detectors.weak_key_size import WeakKeySizeDetector

EDGE_CASES_DIR = Path(__file__).parent.parent / "samples" / "edge_cases"


def test_concatenated_secret_is_not_flagged():
    """Known limitation: secrets built via string concatenation
    (e.g. "abc" + "def") aren't a single string literal, so the
    HARDCODED_KEY regex doesn't match."""
    content = (EDGE_CASES_DIR / "ConcatenatedKey.java").read_text()

    assert HardcodedKeyDetector().scan(content) == []


def test_variable_cipher_transformation_is_not_flagged():
    """Known limitation: Cipher.getInstance(variable) isn't a string
    literal, so ECB_MODE/WEAK_CIPHER can't inspect the transformation
    string without dataflow tracking."""
    content = (EDGE_CASES_DIR / "VariableCipherMode.java").read_text()

    assert EcbModeDetector().scan(content) == []
    assert WeakCipherDetector().scan(content) == []


def test_variable_kdf_iteration_count_is_not_flagged():
    """Known limitation: a PBEKeySpec iteration count passed as a
    variable isn't a literal integer, so WEAK_KDF can't evaluate it."""
    content = (EDGE_CASES_DIR / "VariableIterationCount.java").read_text()

    assert WeakKdfDetector().scan(content) == []


def test_variable_key_size_is_not_flagged():
    """Known limitation: KeyPairGenerator.initialize(variable) isn't a
    literal integer, so WEAK_KEY_SIZE can't evaluate it."""
    content = (EDGE_CASES_DIR / "VariableKeySize.java").read_text()

    assert WeakKeySizeDetector().scan(content) == []


def test_multi_line_field_declaration_is_flagged():
    """Not a limitation — HARDCODED_KEY explicitly handles declarations
    split across lines. Covered in detail in test_hardcoded_keys.py;
    included here so this file is a complete record of the edge-case
    pass across all detectors."""
    content = (EDGE_CASES_DIR / "MultiLineKey.java").read_text()

    findings = HardcodedKeyDetector().scan(content)

    assert len(findings) == 1
    assert findings[0].rule_id == "HARDCODED_KEY"
