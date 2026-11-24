"""Parsing and light validation of Sigma rule YAML files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class SigmaParseError(Exception):
    """Raised when a Sigma rule file cannot be parsed or is missing required fields."""


@dataclass
class SigmaRule:
    title: str
    id: str | None
    description: str | None
    level: str
    logsource: dict
    detection: dict
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def mitre_ids(self) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from tags like 'attack.t1059.001'."""
        ids = []
        for tag in self.tags:
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", tag, re.IGNORECASE)
            if m:
                ids.append(m.group(1).upper())
        return ids


REQUIRED_FIELDS = ("title", "logsource", "detection")


def load_sigma_rule(path: str | Path) -> SigmaRule:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise SigmaParseError(f"Could not read {path}: {e}") from e

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SigmaParseError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(data, dict):
        raise SigmaParseError(f"{path}: top-level YAML must be a mapping")

    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise SigmaParseError(f"{path}: missing required field(s): {', '.join(missing)}")

    detection = data["detection"]
    if "condition" not in detection:
        raise SigmaParseError(f"{path}: detection block is missing a 'condition'")

    return SigmaRule(
        title=data["title"],
        id=data.get("id"),
        description=data.get("description"),
        level=str(data.get("level", "medium")).lower(),
        logsource=data["logsource"],
        detection=detection,
        tags=list(data.get("tags", []) or []),
        falsepositives=list(data.get("falsepositives", []) or []),
        raw=data,
    )


def load_sigma_rules_from_dir(path: str | Path) -> list[tuple[Path, SigmaRule]]:
    path = Path(path)
    results = []
    for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
        results.append((file, load_sigma_rule(file)))
    return results
