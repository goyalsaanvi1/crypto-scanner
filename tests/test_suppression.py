from pathlib import Path

from click.testing import CliRunner

from scanner.cli import main
from scanner.detectors.base import Finding
from scanner.detectors.hardcoded_keys import HardcodedKeyDetector
from scanner.suppression import filter_suppressed_findings

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_same_line_suppression_filters_matching_finding():
    content = 'private static final String KEY = "abc123"; // cryptoscanner: ignore HARDCODED_KEY\n'
    findings = [Finding(line_number=1, rule_id="HARDCODED_KEY", severity="HIGH", message="m")]

    result = filter_suppressed_findings(content, findings)

    assert result == []


def test_prior_line_suppression_filters_matching_finding():
    content = (
        "// cryptoscanner: ignore HARDCODED_KEY\n"
        'private static final String KEY = "abc123";\n'
    )
    findings = [Finding(line_number=2, rule_id="HARDCODED_KEY", severity="HIGH", message="m")]

    result = filter_suppressed_findings(content, findings)

    assert result == []


def test_non_matching_rule_id_does_not_suppress():
    content = 'private static final String KEY = "abc123"; // cryptoscanner: ignore ECB_MODE\n'
    findings = [Finding(line_number=1, rule_id="HARDCODED_KEY", severity="HIGH", message="m")]

    result = filter_suppressed_findings(content, findings)

    assert result == findings


def test_no_directive_does_not_suppress():
    content = 'private static final String KEY = "abc123";\n'
    findings = [Finding(line_number=1, rule_id="HARDCODED_KEY", severity="HIGH", message="m")]

    result = filter_suppressed_findings(content, findings)

    assert result == findings


def test_bare_directive_suppresses_any_rule_on_that_line():
    content = 'private static final String KEY = "abc123"; // cryptoscanner: ignore\n'
    findings = [Finding(line_number=1, rule_id="HARDCODED_KEY", severity="HIGH", message="m")]

    result = filter_suppressed_findings(content, findings)

    assert result == []


def test_sample_file_suppresses_one_field_but_not_the_other():
    content = (SAMPLES_DIR / "vulnerable" / "SuppressedFindings.java").read_text()
    findings = HardcodedKeyDetector().scan(content)

    assert len(findings) == 2

    filtered = filter_suppressed_findings(content, findings)

    assert len(filtered) == 1
    assert "VISIBLE_KEY" in filtered[0].message
    assert "SUPPRESSED_KEY" not in filtered[0].message


def test_cli_exit_code_zero_when_all_findings_suppressed(tmp_path):
    java_file = tmp_path / "AllSuppressed.java"
    java_file.write_text(
        "public class AllSuppressed {\n"
        '    private static final String KEY = "abc123"; // cryptoscanner: ignore HARDCODED_KEY\n'
        "}\n"
    )

    result = CliRunner().invoke(main, [str(java_file)])

    assert result.exit_code == 0
    assert result.output.strip() == ""
