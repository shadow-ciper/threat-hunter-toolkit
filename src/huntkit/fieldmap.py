"""Map Sigma field names onto backend field names.

SIEMs disagree about what a field is called: `src_ip` in Splunk, `source.ip` in
Elastic, `SourceIp` in Windows events. Rewriting a rule by hand for each backend
is where translation mistakes creep in, so the mapping lives in data and the
translation is mechanical.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# Canonical name -> per-backend name. The left-hand side is the normalised form
# every backend maps *into*, so unknown fields can be reported as unmapped
# instead of guessed at.
FIELD_MAP: dict[str, dict[str, str]] = {
    "src_ip": {"splunk": "src_ip", "esql": "source.ip"},
    "dst_ip": {"splunk": "dest_ip", "esql": "destination.ip"},
    "user": {"splunk": "user", "esql": "user.name"},
    "host": {"splunk": "host", "esql": "host.name"},
    "process": {"splunk": "process", "esql": "process.name"},
    "command_line": {"splunk": "process", "esql": "process.command_line"},
    "parent_process": {"splunk": "parent_process", "esql": "process.parent.name"},
    "event_id": {"splunk": "EventCode", "esql": "event.code"},
    "registry_key": {"splunk": "RegistryPath", "esql": "registry.path"},
    "registry_value": {"splunk": "RegistryValueName", "esql": "registry.value.name"},
    "service_name": {"splunk": "ServiceName", "esql": "service.name"},
    "image_path": {"splunk": "Image", "esql": "process.executable"},
    "destination_port": {"splunk": "dest_port", "esql": "destination.port"},
}

BACKENDS = ("splunk", "esql")


@dataclass
class MappingResult:
    fields: dict[str, str]
    unmapped: list[str]

    @property
    def complete(self) -> bool:
        return not self.unmapped


def map_field(name: str, backend: str) -> str | None:
    entry = FIELD_MAP.get(name)
    if entry is None:
        return None
    return entry.get(backend)


def map_fields(names: list[str], backend: str) -> MappingResult:
    if backend not in BACKENDS:
        raise ValueError(f"unknown backend {backend!r}; expected one of {BACKENDS}")

    mapped: dict[str, str] = {}
    unmapped: list[str] = []

    for name in names:
        target = map_field(name, backend)
        if target is None:
            unmapped.append(name)
        else:
            mapped[name] = target

    return MappingResult(fields=mapped, unmapped=unmapped)


def load_overrides(path: str | Path) -> dict[str, dict[str, str]]:
    """Merge a JSON overlay on top of the built-in map.

    Useful because every environment has its own naming. Unmapped fields are the
    common case and an overlay is how you fill them without editing the source.
    """
    with open(path, encoding="utf-8") as fh:
        overlay = json.load(fh)

    if not isinstance(overlay, dict):
        raise ValueError("field map overlay must be a JSON object")

    for canonical, targets in overlay.items():
        if not isinstance(targets, dict):
            raise ValueError(f"overlay entry {canonical!r} must map backend -> field")
        FIELD_MAP.setdefault(canonical, {}).update(targets)

    return FIELD_MAP


def unmapped_fields_in_rule(rule) -> list[str]:
    """Canonical field names a rule uses that the map does not cover."""
    used: set[str] = set()
    for block in list(rule.selections) + list(rule.filters):
        used.update(block.fields)

    return sorted(name for name in used if name not in FIELD_MAP)


def coverage_report() -> str:
    lines = [f"{len(FIELD_MAP)} canonical fields mapped\n"]
    for backend in BACKENDS:
        complete = [c for c, t in FIELD_MAP.items() if backend in t]
        lines.append(f"{backend}: {len(complete)}/{len(FIELD_MAP)} have a target")
    return "\n".join(lines)