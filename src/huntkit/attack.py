"""ATT&CK coverage checking across a directory of Sigma rules.

Reads only local files and a bundled technique list. There is no live ATT&CK
STIX fetch, so coverage is measured against the techniques shipped here and the
tool says which snapshot it used rather than implying it is current.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .sigma import SigmaRule, SigmaParseError, infer_techniques, load

# Minimal technique snapshot: id -> (name, tactic). Carried in-tree so the tool
# runs offline. Version below is what this list was taken from; it is not live.
ATTACK_SNAPSHOT = "v14 (partial: 40 techniques)"

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1021": ("Remote Services", "lateral-movement"),
    "T1021.001": ("Remote Desktop Protocol", "lateral-movement"),
    "T1021.004": ("SSH", "lateral-movement"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1036": ("Masquerading", "defense-evasion"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1055": ("Process Injection", "defense-evasion"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.004": ("Unix Shell", "execution"),
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1069": ("Permission Groups Discovery", "discovery"),
    "T1070": ("Indicator Removal", "defense-evasion"),
    "T1070.003": ("Clear Command History", "defense-evasion"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1078": ("Valid Accounts", "defense-evasion"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1090": ("Proxy", "command-and-control"),
    "T1095": ("Non-Application Layer Protocol", "command-and-control"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1110.003": ("Password Spraying", "credential-access"),
    "T1133": ("External Remote Services", "initial-access"),
    "T1136": ("Create Account", "persistence"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1195": ("Supply Chain Compromise", "initial-access"),
    "T1484": ("Domain Policy Modification", "privilege-escalation"),
    "T1489": ("Service Stop", "impact"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1562.001": ("Impair Defenses", "defense-evasion"),
    "T1566": ("Phishing", "initial-access"),
    "T1566.001": ("Spearphishing Attachment", "initial-access"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
    "T1568": ("Dynamic Resolution", "command-and-control"),
}

TACTICS = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


@dataclass
class Coverage:
    covered: set[str] = field(default_factory=set)
    rules_per_technique: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    untagged: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    def by_tactic(self) -> dict[str, tuple[int, int]]:
        """Tactic -> (covered, total) using the bundled snapshot."""
        result: dict[str, tuple[int, int]] = {}
        for tactic in TACTICS:
            ids = [i for i, (_, t) in TECHNIQUES.items() if t == tactic]
            result[tactic] = (sum(1 for i in ids if i in self.covered), len(ids))
        return result

    @property
    def percent(self) -> float:
        if not TECHNIQUES:
            return 0.0
        return 100.0 * len(self.covered) / len(TECHNIQUES)


def load_directory(root: str | Path, pattern: str = "*.yml") -> Coverage:
    """Parse every rule under `root`.

    Rules that fail to parse are collected rather than aborting the run. A single
    malformed rule should not stop a coverage report, but it must be visible.
    """
    coverage = Coverage()
    root = Path(root)

    for path in sorted(root.rglob(pattern)):
        if path.name.lower() == "sigma.yml":
            continue
        try:
            rule = load(str(path))
        except SigmaParseError as exc:
            coverage.failed.append((str(path), str(exc)))
            continue
        except Exception as exc:  # malformed YAML and similar
            coverage.failed.append((str(path), f"unreadable: {exc}"))
            continue
        _record(coverage, rule, str(path))

    return coverage


def _record(coverage: Coverage, rule: SigmaRule, path: str) -> None:
    techniques = infer_techniques(rule.tags)
    if not techniques:
        coverage.untagged.append(f"{path}: {rule.title}")
        return
    for technique in techniques:
        coverage.covered.add(technique)
        coverage.rules_per_technique[technique].append(rule.title)


def report(coverage: Coverage) -> str:
    lines = [
        f"ATT&CK coverage against bundled snapshot {ATTACK_SNAPSHOT}",
        f"  rules with techniques : {len(coverage.rules_per_technique)}",
        f"  techniques covered    : {len(coverage.covered)}/{len(TECHNIQUES)}"
        f"  ({coverage.percent:.1f}%)",
        f"  rules without a technique tag : {len(coverage.untagged)}",
        f"  rules that failed to parse     : {len(coverage.failed)}",
        "",
    ]

    tactic_rows = coverage.by_tactic()
    lines.append(f"{'tactic':24} {'covered':>8}")
    for tactic, (hit, total) in tactic_rows.items():
        bar = "#" * hit + "." * (total - hit)
        lines.append(f"{tactic:24} {hit:3d}/{total:<4d} {bar}")

    gaps = sorted(set(TECHNIQUES) - coverage.covered)
    if gaps:
        lines.append("\ntechniques with no rule in this directory")
        for technique in gaps:
            name, tactic = TECHNIQUES[technique]
            lines.append(f"  {technique:12} {name} ({tactic})")

    return "\n".join(lines)


def export_json(coverage: Coverage) -> str:
    return json.dumps(
        {
            "snapshot": ATTACK_SNAPSHOT,
            "techniques_total": len(TECHNIQUES),
            "techniques_covered": sorted(coverage.covered),
            "percent": round(coverage.percent, 1),
            "by_tactic": coverage.by_tactic(),
            "rules_per_technique": dict(coverage.rules_per_technique),
            "untagged_rules": coverage.untagged,
            "failed_rules": [{"path": p, "error": e} for p, e in coverage.failed],
        },
        indent=2,
    )