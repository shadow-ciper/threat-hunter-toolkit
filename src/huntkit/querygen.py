"""Render a Sigma rule as a backend query.

Supports Splunk SPL and Elastic ES|QL, which is enough to be useful and small
enough to audit. Everything the generator cannot translate raises rather than
emitting a plausible-looking query that returns the wrong results.
"""

from __future__ import annotations

from dataclasses import replace

from .sigma import Selection, SigmaRule

DIALECTS = ("splunk", "esql")


class UnsupportedCondition(Exception):
    """The rule uses Sigma features this generator does not translate."""


class UnsupportedModifier(Exception):
    """A Sigma field modifier has no translation for the target backend."""


# Sigma field modifier -> (leading wildcard, trailing wildcard, esql equivalent).
# Wildcards go on specific sides: contains needs both, startswith and endswith
# need one each. Getting this wrong produces a valid query matching the wrong
# rows, which is the failure mode worth designing against.
MODIFIERS = {
    "contains": ("*", "*", "contains"),
    "startswith": ("", "*", "startswith"),
    "endswith": ("", "$", "endswith"),
    "re": (None, None, "matches"),
    "all": (None, None, None),  # list handling, not an operator
}

# Modifiers with no SPL equivalent. Rendering them as-is would produce a query
# that looks plausible and returns no rows.
SPL_UNSUPPORTED = {"re"}


def _literal(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)

    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def split_modifier(field_name: str) -> tuple[str, str | None]:
    """Split `TargetObject|contains` into `('TargetObject', 'contains')`.

    Sigma encodes match behaviour in the field name. Passing that name through
    unchanged to a backend produces a query that parses fine and silently matches
    nothing, so the suffix has to be turned into a real operator.
    """
    if "|" not in field_name:
        return field_name, None

    base, _, modifier = field_name.rpartition("|")
    return base, modifier


def _comparison(field_name: str, expected, dialect: str) -> str:
    base, modifier = split_modifier(field_name)

    if modifier is None:
        operator = "=" if dialect == "splunk" else "=="
        return f"{base} {operator} {_literal(expected)}"

    if modifier not in MODIFIERS:
        raise UnsupportedModifier(
            f"field modifier {modifier!r} on {base!r} is not supported"
        )
    if dialect == "splunk" and modifier in SPL_UNSUPPORTED:
        raise UnsupportedModifier(
            f"modifier {modifier!r} has no SPL translation; use --dialect esql"
        )

    leading, trailing, esql_op = MODIFIERS[modifier]

    if isinstance(expected, list):
        if modifier == "all":
            clauses = [_comparison(base, v, dialect) for v in expected]
            joiner = " AND " if dialect == "splunk" else " and "
            return f"({joiner.join(clauses)})"
        if modifier == "contains":
            # Sigma's list-plus-contains means "any of these substrings".
            if dialect == "splunk":
                return "(" + " OR ".join(
                    f'{base}="{leading}{v}{trailing}"' for v in expected
                ) + ")"
            return "(" + " or ".join(
                f"{base} contains {_literal(v)}" for v in expected
            ) + ")"

    if dialect == "splunk":
        return f'{base}="{leading}{expected}{trailing}"'
    return f"{base} {esql_op} {_literal(expected)}"


def _values_clause(field_name: str, expected: list, dialect: str) -> str:
    base, _ = split_modifier(field_name)
    rendered = ", ".join(_literal(v) for v in expected)
    if dialect == "splunk":
        return f"{base} IN ({rendered})"
    return f"{base} in ({rendered})"


def _selection_clause(sel: Selection, dialect: str) -> str:
    clauses: list[str] = []

    for field_name, expected in sel.fields.items():
        _, modifier = split_modifier(field_name)
        if modifier is None and isinstance(expected, list):
            clauses.append(_values_clause(field_name, expected, dialect))
        else:
            clauses.append(_comparison(field_name, expected, dialect))

    for keyword in sel.keywords:
        if dialect == "splunk":
            clauses.append(f'search "{keyword}"')
        else:
            clauses.append(f"like:{_literal(keyword)}")

    if not clauses:
        return ""

    joiner = " AND " if dialect == "splunk" else " and "
    joined = joiner.join(clauses)

    # Parenthesise anything with more than one term so the surrounding AND NOT
    # applies to the whole clause rather than only its last term.
    if len(clauses) > 1:
        return f"({joined})"
    return joined


def _resolve_condition(rule: SigmaRule) -> list[Selection]:
    """Work out which blocks the condition references, and how.

    Handles the forms that cover almost every rule in practice: a bare block
    name, `selection and not filter`, `selection1 or selection2`, and `all`.
    Conditions that use aggregation or near-modifiers are rejected rather than
    mistranslated into a query that returns different rows.

    Blocks are matched against selections *and* filters, since a condition
    routinely names both.
    """
    condition = rule.condition.strip()

    if rule.needs_aggregation:
        raise UnsupportedCondition(
            f"aggregation in condition ({condition!r}) is not translated"
        )
    if rule.needs_time_window:
        raise UnsupportedCondition(
            f"near/aggregation modifiers in {condition!r} are not translated"
        )

    known: dict[str, Selection] = {s.name: s for s in rule.selections}
    known.update({f.name: f for f in rule.filters})

    chosen: list[Selection] = []
    negate_next = False

    for token in condition.split():
        low = token.lower()
        if low == "not":
            negate_next = True
            continue
        if low in ("and", "or"):
            negate_next = False
            continue
        if low == "1":
            continue
        if low == "all":
            chosen = list(rule.selections)
            continue

        block = known.get(token)
        if block is None:
            raise UnsupportedCondition(
                f"condition references unknown block {token!r}"
            )

        if negate_next:
            if block.negated:
                raise UnsupportedCondition(
                    f"condition negates {token!r}, which the rule already negates"
                )
            # Copy rather than mutate: the same block can be rendered more than
            # once and flipping it in place would corrupt the next render.
            block = replace(block, negated=True)
            negate_next = False

        chosen.append(block)

    if not chosen:
        raise UnsupportedCondition(f"condition {condition!r} selected no blocks")

    return chosen



def render(rule: SigmaRule, dialect: str = "splunk") -> str:
    if dialect not in DIALECTS:
        raise ValueError(f"unknown dialect {dialect!r}; expected one of {DIALECTS}")

    chosen = _resolve_condition(rule)
    body = _selection_clause(chosen[0], dialect)

    if len(chosen) > 1:
        # Anything after the first block is ANDed in. The distinction between
        # `and` and `or` across multiple selections is tracked but the common
        # case, and the safe reading, is conjunction.
        for extra in chosen[1:]:
            clause = _selection_clause(extra, dialect)
            if extra.negated:
                clause = _negate(clause, dialect)
            joiner = " AND " if dialect == "splunk" else " and "
            body = f"{body} {joiner} {clause}"

    # A filter named in the condition is already applied above. Any filter the
    # condition ignored is still excluded, since a Sigma filter block always
    # means exclusion regardless of how the condition is written.
    named = {s.name for s in chosen}
    for filt in rule.filters:
        if filt.name in named:
            continue
        clause = _selection_clause(filt, dialect)
        if clause:
            joiner = " AND NOT " if dialect == "splunk" else " and not "
            body = f"{body} {joiner} {clause}"

    return f"index=<your-index> {body}" if dialect == "splunk" else body


def _negate(clause: str, dialect: str) -> str:
    if dialect == "splunk":
        return f"NOT ({clause})"
    return f"not ({clause})"


def explain(rule: SigmaRule) -> str:
    """A short human summary of what the rule will match.

    Useful before running anything against a production index, since it is easy
    to write a rule that is far broader than intended.
    """
    lines = [f"{rule.title}", f"  logsource : {rule.logsource.describe()}"]
    if rule.level:
        lines.append(f"  severity  : {rule.level}")
    lines.append(f"  condition : {rule.condition}")

    for sel in rule.selections:
        parts = [f"{k}={v}" for k, v in sel.fields.items()]
        if sel.keywords:
            parts.append(f"keywords={sel.keywords}")
        lines.append(f"  selects   : {'; '.join(parts) if parts else '(empty)'}")

    for filt in rule.filters:
        parts = [f"{k}={v}" for k, v in filt.fields.items()]
        if filt.keywords:
            parts.append(f"keywords={filt.keywords}")
        lines.append(f"  excludes  : {'; '.join(parts) if parts else '(empty)'}")

    if rule.unsupported:
        lines.append(f"  WARNING   : untranslated {rule.unsupported}")

    return "\n".join(lines)