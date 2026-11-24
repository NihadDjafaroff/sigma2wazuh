"""Top-level conversion API: Sigma rule file(s) -> Wazuh local_rules.xml."""

from __future__ import annotations

from pathlib import Path

from .detection import ConversionError, detection_to_selection
from .sigma_parser import SigmaParseError, SigmaRule, load_sigma_rule, load_sigma_rules_from_dir
from .wazuh_writer import build_converted_rules, render_group_xml, render_rule_xml

DEFAULT_GROUP_NAME = "sigma_converted"


class ConversionWarning:
    def __init__(self, rule_title: str, message: str):
        self.rule_title = rule_title
        self.message = message

    def __str__(self):
        return f"[{self.rule_title}] {self.message}"


def convert_rule(rule: SigmaRule, start_id: int) -> tuple[str, int, list[ConversionWarning]]:
    """Convert one SigmaRule. Returns (xml_rule_blocks_joined, next_free_id, warnings)."""
    warnings: list[ConversionWarning] = []
    selection = detection_to_selection(rule.detection)
    if len(selection) > 1:
        warnings.append(
            ConversionWarning(
                rule.title,
                f"condition resolves to an OR of {len(selection)} groups; "
                f"Wazuh cannot express this in one rule, so {len(selection)} "
                "sibling rules were generated instead.",
            )
        )
    converted = build_converted_rules(rule, selection, start_id)
    blocks = [render_rule_xml(cr, rule.id) for cr in converted]
    return "\n\n".join(blocks), start_id + len(converted), warnings


def convert_file(
    path: str | Path, start_id: int = 100100, group_name: str = DEFAULT_GROUP_NAME
) -> tuple[str, list[ConversionWarning]]:
    rule = load_sigma_rule(path)
    xml_block, _next_id, warnings = convert_rule(rule, start_id)
    return render_group_xml(group_name, [xml_block]), warnings


def convert_directory(
    path: str | Path, start_id: int = 100100, group_name: str = DEFAULT_GROUP_NAME
) -> tuple[str, list[ConversionWarning], list[tuple[Path, Exception]]]:
    rules = load_sigma_rules_from_dir(path)
    blocks = []
    all_warnings: list[ConversionWarning] = []
    errors: list[tuple[Path, Exception]] = []
    next_id = start_id
    for file_path, rule in rules:
        try:
            xml_block, next_id, warnings = convert_rule(rule, next_id)
            blocks.append(xml_block)
            all_warnings.extend(warnings)
        except (ConversionError, SigmaParseError) as e:
            errors.append((file_path, e))
    xml = render_group_xml(group_name, blocks) if blocks else ""
    return xml, all_warnings, errors
