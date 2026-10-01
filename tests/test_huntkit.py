import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntkit import attack, fieldmap, querygen
from huntkit.sigma import SigmaParseError, from_dict, infer_techniques

RULES = Path(__file__).resolve().parents[1] / "samples" / "rules"


def rule_from(**overrides):
    data = {
        "title": "Test Rule",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
    }
    data.update(overrides)
    return from_dict(data)


# --- sigma parsing ---


def test_parses_title_and_logsource():
    rule = rule_from()
    assert rule.title == "Test Rule"
    assert rule.logsource.product == "windows"
    assert rule.logsource.category == "process_creation"


def test_logsource_describe():
    rule = rule_from()
    assert rule.logsource.describe() == "windows/process_creation"


def test_missing_detection_raises():
    with pytest.raises(SigmaParseError, match="no detection block"):
        from_dict({"title": "no detection"})


def test_missing_selection_raises():
    with pytest.raises(SigmaParseError, match="no selection block"):
        from_dict({"title": "x", "detection": {"condition": "selection"}})


def test_unrecognised_block_is_reported_not_dropped():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"a": "b"}, "weirdblock": [{"c": "d"}], "condition": "selection"},
    })
    assert any("weirdblock" in u for u in rule.unsupported)


def test_near_is_flagged_unsupported():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"a": "b"}, "condition": "selection", "near": "5m"},
    })
    assert any("near" in u for u in rule.unsupported)


def test_technique_inference_only_accepts_explicit_tags():
    assert infer_techniques(["attack.t1059.001", "attack.execution"]) == ["T1059.001"]
    assert infer_techniques(["attack.execution"]) == []


# --- query generation ---


def test_simple_rule_renders_splunk():
    rule = rule_from()
    out = querygen.render(rule, "splunk")
    assert "index=<your-index>" in out
    assert "cmd.exe" in out


def test_contains_modifier_becomes_a_wildcard_not_a_field_name():
    # Regression: modifiers were passed through as part of the field name, which
    # parses fine in SPL and silently matches nothing.
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"CommandLine|contains": "whoami"}, "condition": "selection"},
    })
    out = querygen.render(rule, "splunk")
    assert 'CommandLine|"whoami"' not in out
    assert 'CommandLine="*whoami*"' in out


def test_endswith_modifier_becomes_a_suffix_wildcard():
    # Regression: bracketing a symmetric marker put a wildcard on both sides, so
    # endswith rendered as contains and matched more than it should.
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
    })
    assert 'Image="\\cmd.exe$"' in querygen.render(rule, "splunk")


def test_startswith_modifier_puts_the_wildcard_on_the_correct_side():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"TargetFilename|startswith": "C:\\Temp"}, "condition": "selection"},
    })
    out = querygen.render(rule, "splunk")
    assert 'TargetFilename="C:\\Temp*"' in out
    assert "Temp*$" not in out


def test_contains_list_becomes_any_of():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"CommandLine|contains": [" -enc ", " -EncodedCommand "]},
            "condition": "selection",
        },
    })
    out = querygen.render(rule, "splunk")
    assert " OR " in out
    assert "CommandLine|contains" not in out


def test_unknown_modifier_is_refused():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"Field|bogusmod": "y"}, "condition": "selection"},
    })
    with pytest.raises(querygen.UnsupportedModifier, match="bogusmod"):
        querygen.render(rule, "splunk")


def test_regex_modifier_refused_for_splunk_but_ok_for_esql():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"CommandLine|re": "whoami|id"}, "condition": "selection"},
    })
    with pytest.raises(querygen.UnsupportedModifier, match="no SPL translation"):
        querygen.render(rule, "splunk")
    assert "matches" in querygen.render(rule, "esql")


def test_multi_clause_selection_is_parenthesised():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4656, "Image|endswith": "\\lsass.exe"},
            "filter": {"SourceImage|contains": "w3wp.exe"},
            "condition": "selection and not filter",
        },
    })
    out = querygen.render(rule, "splunk")
    # The multi-term selection must be parenthesised so AND NOT applies to the
    # whole block, not just its final term.
    assert "(EventID = 4656 AND Image=" in out
    assert "AND  NOT (SourceImage=" in out


def test_list_field_becomes_in_clause():
    # A plain list field has no modifier, so it becomes a membership test.
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"Port": [80, 443]}, "condition": "selection"},
    })
    assert "Port IN (80, 443)" in querygen.render(rule, "splunk")


def test_filter_is_applied_as_negation():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4656},
            "filter": {"SourceImage": "C:\\test.exe"},
            "condition": "selection and not filter",
        },
    })
    out = querygen.render(rule, "splunk")
    assert "NOT (SourceImage" in out


def test_esql_uses_equality():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 4656}, "condition": "selection"},
    })
    assert "EventID == 4656" in querygen.render(rule, "esql")


def test_aggregation_condition_is_refused():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"a": "b"}, "condition": "selection | count() > 5"},
    })
    with pytest.raises(querygen.UnsupportedCondition, match="aggregation"):
        querygen.render(rule, "splunk")


def test_unknown_condition_block_is_refused():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"a": "b"},
            "selection2": {"c": "d"},
            "condition": "nonexistent",
        },
    })
    with pytest.raises(querygen.UnsupportedCondition, match="unknown block"):
        querygen.render(rule, "splunk")


def test_unknown_dialect_raises():
    rule = rule_from()
    with pytest.raises(ValueError, match="unknown dialect"):
        querygen.render(rule, "kibana")


def test_quotes_are_escaped():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"field": 'say "hi"'}, "condition": "selection"},
    })
    assert '\\"hi\\"' in querygen.render(rule, "splunk")


def test_explain_warns_on_unsupported():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"a": "b"}, "condition": "selection", "near": "5m"},
    })
    assert "WARNING" in querygen.explain(rule)


# --- field mapping ---


def test_known_field_maps_per_backend():
    assert fieldmap.map_field("src_ip", "splunk") == "src_ip"
    assert fieldmap.map_field("src_ip", "esql") == "source.ip"


def test_unknown_field_returns_none():
    assert fieldmap.map_field("not_a_field", "splunk") is None


def test_map_fields_reports_unmapped():
    result = fieldmap.map_fields(["src_ip", "mystery_field"], "splunk")
    assert "src_ip" in result.fields
    assert result.unmapped == ["mystery_field"]
    assert not result.complete


def test_unmapped_fields_in_rule():
    rule = from_dict({
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"src_ip": "1.2.3.4", "weird": "y"}, "condition": "selection"},
    })
    assert fieldmap.unmapped_fields_in_rule(rule) == ["weird"]


def test_overlay_extends_the_map(tmp_path):
    overlay = tmp_path / "overlay.json"
    overlay.write_text('{"custom_field": {"splunk": "custom"}}')
    fieldmap.load_overrides(str(overlay))
    assert fieldmap.map_field("custom_field", "splunk") == "custom"


def test_coverage_report_lists_backends():
    assert "splunk" in fieldmap.coverage_report()


# --- coverage ---


def test_coverage_over_sample_rules():
    coverage = attack.load_directory(RULES)
    assert "T1003.001" in coverage.covered
    assert "T1059.001" in coverage.covered
    assert coverage.percent > 0


def test_coverage_reports_failures_separately(tmp_path):
    (tmp_path / "broken.yml").write_text("title: broken\ndetection: [not, a, mapping]\n")
    coverage = attack.load_directory(tmp_path)
    assert len(coverage.failed) == 1


def test_coverage_tracks_untagged_rules(tmp_path):
    (tmp_path / "untagged.yml").write_text(
        "title: no tags\n"
        "logsource:\n    product: windows\n"
        "detection:\n    selection:\n        a: b\n"
        "    condition: selection\n"
    )
    coverage = attack.load_directory(tmp_path)
    assert len(coverage.untagged) == 1


def test_every_sample_rule_parses():
    coverage = attack.load_directory(RULES)
    assert coverage.failed == [], f"sample rules failed: {coverage.failed}"


def test_coverage_json_is_valid():
    import json
    coverage = attack.load_directory(RULES)
    data = json.loads(attack.export_json(coverage))
    assert data["techniques_total"] > 0
    assert "by_tactic" in data