import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from scanner.cli import main
from scanner.config import ConfigError, load_config

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _write_config(directory: Path, contents: str) -> None:
    (directory / ".cryptoscanner.yml").write_text(textwrap.dedent(contents))


def _run_cli(args):
    return CliRunner().invoke(main, args)


def test_no_config_file_all_rules_enabled_at_default(tmp_path):
    config = load_config(tmp_path)

    assert config.is_enabled("ECB_MODE") is True
    assert config.is_enabled("WEAK_HASH") is True
    assert config.severity_override("WEAK_HASH") is None


def test_config_disables_one_rule_others_stay_enabled(tmp_path):
    _write_config(
        tmp_path,
        """
        rules:
          ECB_MODE:
            enabled: false
        """,
    )

    config = load_config(tmp_path)

    assert config.is_enabled("ECB_MODE") is False
    assert config.is_enabled("HARDCODED_KEY") is True
    assert config.is_enabled("WEAK_HASH") is True


def test_config_severity_override(tmp_path):
    _write_config(
        tmp_path,
        """
        rules:
          WEAK_HASH:
            enabled: true
            severity_override: HIGH
        """,
    )

    config = load_config(tmp_path)

    assert config.is_enabled("WEAK_HASH") is True
    assert config.severity_override("WEAK_HASH") == "HIGH"


def test_malformed_yaml_raises_config_error(tmp_path):
    _write_config(tmp_path, "rules: [this is not: a valid mapping")

    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_unknown_rule_id_raises_config_error(tmp_path):
    _write_config(
        tmp_path,
        """
        rules:
          NOT_A_REAL_RULE:
            enabled: false
        """,
    )

    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_unknown_setting_raises_config_error(tmp_path):
    _write_config(
        tmp_path,
        """
        rules:
          ECB_MODE:
            severty: false
        """,
    )

    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_cli_skips_disabled_detector_but_runs_others(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_config(
        tmp_path,
        """
        rules:
          ECB_MODE:
            enabled: false
        """,
    )

    target = SAMPLES_DIR / "vulnerable" / "EcbExample.java"
    result = _run_cli([str(target)])

    assert "ECB_MODE" not in result.output
    # EcbExample.java's only finding is ECB_MODE, now disabled, so the run is clean.
    assert result.exit_code == 0


def test_cli_applies_severity_override_to_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_config(
        tmp_path,
        """
        rules:
          WEAK_HASH:
            severity_override: HIGH
        """,
    )

    target = SAMPLES_DIR / "safe" / "ChecksumExample.java"
    result = _run_cli([str(target)])

    assert "[WEAK_HASH] HIGH" in result.output


def test_cli_malformed_config_reports_clear_error_not_traceback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_config(
        tmp_path,
        """
        rules:
          NOT_A_RULE:
            enabled: false
        """,
    )

    target = SAMPLES_DIR / "safe" / "GcmExample.java"
    result = _run_cli([str(target)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "NOT_A_RULE" in result.output
