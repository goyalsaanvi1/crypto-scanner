from dataclasses import dataclass, field
from pathlib import Path

import yaml

from scanner.report import RULE_IDS

CONFIG_FILENAME = ".cryptoscanner.yml"

_VALID_SEVERITIES = ("HIGH", "MEDIUM", "LOW")
_VALID_RULE_SETTINGS = {"enabled", "severity_override"}


class ConfigError(Exception):
    """Raised when .cryptoscanner.yml is missing/malformed or references
    an unknown rule_id."""


@dataclass
class RuleConfig:
    enabled: bool = True
    severity_override: str | None = None


@dataclass
class ScannerConfig:
    rules: dict[str, RuleConfig] = field(default_factory=dict)

    def is_enabled(self, rule_id: str) -> bool:
        rule = self.rules.get(rule_id)
        return rule.enabled if rule else True

    def severity_override(self, rule_id: str) -> str | None:
        rule = self.rules.get(rule_id)
        return rule.severity_override if rule else None


def load_config(directory: Path) -> ScannerConfig:
    """Loads .cryptoscanner.yml from `directory` if present. Returns a
    default (all rules enabled, no overrides) ScannerConfig if the file
    doesn't exist. Raises ConfigError on malformed YAML or unknown
    rule_ids/settings."""
    config_path = directory / CONFIG_FILENAME
    if not config_path.exists():
        return ScannerConfig()

    try:
        raw = yaml.safe_load(config_path.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError(f"{CONFIG_FILENAME} is not valid YAML: {exc}") from exc

    return _parse_config(raw)


def _parse_config(raw) -> ScannerConfig:
    if raw is None:
        return ScannerConfig()

    if not isinstance(raw, dict):
        raise ConfigError(f"{CONFIG_FILENAME} must be a YAML mapping at the top level.")

    rules_raw = raw.get("rules") or {}
    if not isinstance(rules_raw, dict):
        raise ConfigError(f"'rules' in {CONFIG_FILENAME} must be a mapping of rule_id -> settings.")

    rules = {}
    for rule_id, settings in rules_raw.items():
        if rule_id not in RULE_IDS:
            known = ", ".join(RULE_IDS)
            raise ConfigError(
                f"Unknown rule_id '{rule_id}' in {CONFIG_FILENAME}. "
                f"Known rule_ids: {known}"
            )

        settings = settings or {}
        if not isinstance(settings, dict):
            raise ConfigError(f"Settings for rule '{rule_id}' in {CONFIG_FILENAME} must be a mapping.")

        unknown_keys = set(settings) - _VALID_RULE_SETTINGS
        if unknown_keys:
            raise ConfigError(
                f"Unknown setting(s) {sorted(unknown_keys)} for rule "
                f"'{rule_id}' in {CONFIG_FILENAME}. Valid settings: "
                f"{sorted(_VALID_RULE_SETTINGS)}."
            )

        enabled = settings.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(
                f"'enabled' for rule '{rule_id}' in {CONFIG_FILENAME} must be true or false."
            )

        severity_override = settings.get("severity_override")
        if severity_override is not None:
            if (
                not isinstance(severity_override, str)
                or severity_override.upper() not in _VALID_SEVERITIES
            ):
                raise ConfigError(
                    f"'severity_override' for rule '{rule_id}' in "
                    f"{CONFIG_FILENAME} must be one of {_VALID_SEVERITIES}."
                )
            severity_override = severity_override.upper()

        rules[rule_id] = RuleConfig(enabled=enabled, severity_override=severity_override)

    return ScannerConfig(rules=rules)
