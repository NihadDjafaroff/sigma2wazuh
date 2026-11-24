"""Renders a parsed+converted Sigma rule as Wazuh local_rules.xml <rule> blocks."""

from __future__ import annotations

from dataclasses import dataclass
from xml.sax.saxutils import escape, quoteattr

from .detection import AndGroup, Selection
from .sigma_parser import SigmaRule

# Sigma level -> Wazuh rule level (0-15 scale). Approximate, commonly used mapping.
LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 15,
}


@dataclass
class ConvertedRule:
    rule_id: int
    level: int
    description: str
    group_leaves: AndGroup
    mitre_ids: list[str]
    is_or_branch: bool
    branch_index: int
    branch_total: int


def sigma_level_to_wazuh(level: str) -> int:
    return LEVEL_MAP.get(level.lower(), 8)


def build_converted_rules(
    rule: SigmaRule, selection: Selection, start_id: int
) -> list[ConvertedRule]:
    """Selection is an OR of AND-groups; each AND-group becomes one Wazuh rule.
    When there is more than one group, Wazuh cannot express the OR inside a
    single rule, so we emit N sibling rules, each tagged as an OR branch.
    """
    level = sigma_level_to_wazuh(rule.level)
    total = len(selection)
    converted = []
    for i, group in enumerate(selection):
        desc = rule.title
        if total > 1:
            desc = f"{rule.title} (OR branch {i + 1}/{total})"
        converted.append(
            ConvertedRule(
                rule_id=start_id + i,
                level=level,
                description=desc,
                group_leaves=group,
                mitre_ids=rule.mitre_ids,
                is_or_branch=total > 1,
                branch_index=i + 1,
                branch_total=total,
            )
        )
    return converted


def render_rule_xml(cr: ConvertedRule, sigma_id: str | None, indent: str = "  ") -> str:
    lines = [f'{indent}<rule id="{cr.rule_id}" level="{cr.level}">']
    for leaf in cr.group_leaves:
        negate_attr = ' negate="yes"' if leaf.negate else ""
        lines.append(
            f'{indent}  <field name={quoteattr(leaf.wazuh_field)} type="pcre2"{negate_attr}>'
            f"{escape(leaf.pattern)}</field>"
        )
    lines.append(f"{indent}  <description>{escape(cr.description)}</description>")
    if sigma_id:
        lines.append(f"{indent}  <!-- sigma_id: {escape(sigma_id)} -->")
    if cr.mitre_ids:
        lines.append(f"{indent}  <mitre>")
        for mid in cr.mitre_ids:
            lines.append(f"{indent}    <id>{escape(mid)}</id>")
        lines.append(f"{indent}  </mitre>")
    lines.append(f"{indent}</rule>")
    return "\n".join(lines)


def render_group_xml(group_name: str, rule_blocks: list[str]) -> str:
    body = "\n\n".join(rule_blocks)
    return f'<group name="{escape(group_name)},">\n\n{body}\n\n</group>'
