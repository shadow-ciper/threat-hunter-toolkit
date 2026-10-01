"""Sigma rule parsing.

Sigma's YAML schema is large and this covers the parts a detection engineer
actually types: logsource, detection with selection/filter/condition, and
keywords. Anything unsupported is reported rather than silently dropped, since
a rule that parses into the wrong thing is worse than one that fails loudly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


class SigmaParseError(Exception):
    """Raised when a rule cannot be parsed with confidence."""


@dataclass
class Selection:
    """One selection block: a conjunction of fields, or a keyword list."""

    name: str
    fields: dict[str, Any] = field(default_factory=dict)
    keywords: list[str] = field(default_factory=list)
    negated: bool = False


@dataclass
class LogSource:
    product: str | None = None
    category: str | None = None
    service: str | None = None
    definition: str | None = None

    def describe(self) -> str:
        parts = [p for p in (self.product, self.service, self.category) if p]
        return "/".join(parts) if parts else "unspecified"

    def matches(self, other: "LogSource") -> bool:
        """Whether `other` is compatible with this logsource.

        Unset fields on either side are treated as a wildcard, so a rule that
        only names a category can run against a source that also names a
        product. Two conflicting values never match.
        """
        for a, b in (
            (self.product, other.product),
            (self.category, other.category),
            (self.service, other.service),
        ):
            if a and b and a.lower() != b.lower():
                return False
        return True


@dataclass
class SigmaRule:
    title: str
    id: str | None
    status: str | None
    level: str | None
    description: str
    logsource: LogSource
    selections: list[Selection] = field(default_factory=list)
    filters: list[Selection] = field(default_factory=list)
    condition: str = ""
    tags: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    @property
    def needs_aggregation(self) -> bool:
        return bool(re.search(r"\b(count|sum|avg|min|max)\b", self.condition))

    @property
    def needs_time_window(self) -> bool:
        return "|" in self.condition


def load(path: str) -> SigmaRule:
    if yaml is None:
        raise SigmaParseError("PyYAML is required to parse Sigma rules")
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise SigmaParseError(f"{path}: top level must be a mapping")
    return from_dict(data)


def from_dict(data: dict[str, Any]) -> SigmaRule:
    detection = data.get("detection")
    if not isinstance(detection, dict):
        raise SigmaParseError("rule has no detection block")

    selections = []
    filters = []
    unsupported = []

    for key, value in detection.items():
        if key in ("condition", "timeframe", "near", "aggregate"):
            if key in ("near", "aggregate"):
                unsupported.append(f"detection.{key}")
            continue

        # Sigma allows a selection to be a single mapping of fields instead of a
        # list containing one. A dict is normalised to a one-item list so both
        # spellings parse the same way.
        if isinstance(value, dict):
            value = [value]

        if not isinstance(value, list):
            unsupported.append(f"detection.{key} (expected a list or mapping)")
            continue

        if key.startswith("filter"):
            filters.append(_build_selection(key, value))
        elif key.startswith("selection"):
            selections.append(_build_selection(key, value))
        else:
            unsupported.append(f"detection.{key} (unrecognised block)")

    if not selections:
        raise SigmaParseError("rule has no selection block")

    return SigmaRule(
        title=str(data.get("title", "<untitled>")),
        id=data.get("id"),
        status=data.get("status"),
        level=data.get("level"),
        description=str(data.get("description", "")).strip(),
        logsource=_build_logsource(data.get("logsource")),
        selections=selections,
        filters=filters,
        condition=str(detection.get("condition", "selection")),
        tags=list(data.get("tags", []) or []),
        false_positives=list(data.get("false_positives", []) or []),
        unsupported=unsupported,
    )


def _build_logsource(raw: Any) -> LogSource:
    if not isinstance(raw, dict):
        return LogSource()
    return LogSource(
        product=raw.get("product"),
        category=raw.get("category"),
        service=raw.get("service"),
        definition=raw.get("definition"),
    )


def _build_selection(name: str, value: list) -> Selection:
    """Split a selection list into field matchers and keyword matchers."""
    fields: dict[str, Any] = {}
    keywords: list[str] = []

    for item in value:
        if isinstance(item, dict):
            for field_name, expected in item.items():
                fields[field_name] = expected
        elif isinstance(item, str):
            keywords.append(item)
        else:
            keywords.append(str(item))

    return Selection(name=name, fields=fields, keywords=keywords)


def infer_techniques(tags: list[str]) -> list[str]:
    """Pull ATT&CK technique IDs out of a rule's tags.

    Only the explicit `attack.tXXXX` form is recognised. Guessing from the title
    would produce confident-looking but wrong technique mappings, which is worse
    than reporting none. The technique ID is upper-cased because Sigma tags are
    written in lowercase and the technique tables are keyed in uppercase.
    """
    found = []
    for tag in tags:
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
        if match:
            found.append(match.group(1).upper())
    return found