"""
Converts a Sigma `detection` block into a normal form:

    Selection  = OR of AndGroups
    AndGroup   = list of Leaf conditions (all must match)
    Leaf       = one field/regex/negate match

This lets a single Sigma rule become either one Wazuh <rule> (when there is
only one AndGroup) or several Wazuh <rule> elements chained to express an OR
that Wazuh's XML schema cannot express within a single rule.

Supported condition syntax (intentionally scoped, not the full Sigma spec):
    "selection"
    "selA and selB [and selC ...]"
    "selA or selB [or selC ...]"
    "not selection"                      (only for a single-leaf selection)
    "1 of them" / "all of them"
    "1 of sel*" / "all of sel*"           (prefix wildcard over selection names)

Anything more complex raises ConversionError with a clear message rather than
silently producing a wrong rule.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from itertools import product

from .field_map import map_field


class ConversionError(Exception):
    pass


@dataclass(frozen=True)
class Leaf:
    sigma_field: str
    wazuh_field: str
    pattern: str
    negate: bool = False


AndGroup = list[Leaf]
Selection = list[AndGroup]  # OR of AND-groups


_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}


def _escape_literal(value) -> str:
    return re.escape(str(value))


def _value_to_patterns(field_key: str, value) -> tuple[list[str], bool]:
    """Return (list of regex fragments for each value, all_required).

    all_required=True means every fragment must match (AND), otherwise any one
    fragment matching is sufficient (OR) — this becomes one Leaf with an
    alternation when all_required is False.
    """
    parts = field_key.split("|")
    modifiers = set(parts[1:])
    unknown = modifiers - _MODIFIERS
    if unknown:
        raise ConversionError(f"unsupported Sigma modifier(s) on '{field_key}': {unknown}")

    values = value if isinstance(value, list) else [value]

    def wrap(v) -> str:
        if "re" in modifiers:
            return str(v)  # raw regex, not escaped
        literal = _escape_literal(v)
        if "contains" in modifiers:
            return literal
        if "startswith" in modifiers:
            return f"^{literal}"
        if "endswith" in modifiers:
            return f"{literal}$"
        # plain/no modifier -> exact match
        return f"^{literal}$"

    fragments = [wrap(v) for v in values]
    all_required = "all" in modifiers
    return fragments, all_required


def _field_base_name(field_key: str) -> str:
    return field_key.split("|")[0]


def _dict_block_to_and_group(block: dict) -> AndGroup:
    leaves: list[Leaf] = []
    for field_key, value in block.items():
        base = _field_base_name(field_key)
        wazuh_field = map_field(base)
        fragments, all_required = _value_to_patterns(field_key, value)
        if all_required:
            # every value must independently match -> one Leaf per fragment, ANDed
            for frag in fragments:
                leaves.append(Leaf(base, wazuh_field, f"(?i){frag}"))
        else:
            pattern = fragments[0] if len(fragments) == 1 else "(?:" + "|".join(fragments) + ")"
            leaves.append(Leaf(base, wazuh_field, f"(?i){pattern}"))
    return leaves


def _block_to_selection(block) -> Selection:
    """A Sigma selection value can be a dict (AND of fields) or a list of dicts
    (OR of AND-blocks)."""
    if isinstance(block, dict):
        return [_dict_block_to_and_group(block)]
    if isinstance(block, list):
        groups: Selection = []
        for item in block:
            if not isinstance(item, dict):
                raise ConversionError("list-style selection items must be mappings")
            groups.append(_dict_block_to_and_group(item))
        return groups
    raise ConversionError(f"unsupported selection value type: {type(block)!r}")


def _combine_and(a: Selection, b: Selection) -> Selection:
    return [ga + gb for ga, gb in product(a, b)]


def _combine_or(a: Selection, b: Selection) -> Selection:
    return a + b


def _negate_selection(sel: Selection) -> Selection:
    if len(sel) != 1 or len(sel[0]) != 1:
        raise ConversionError(
            "'not' is only supported on a selection with exactly one field condition"
        )
    leaf = sel[0][0]
    return [[Leaf(leaf.sigma_field, leaf.wazuh_field, leaf.pattern, negate=True)]]


def detection_to_selection(detection: dict) -> Selection:
    condition = str(detection["condition"]).strip()
    named_blocks = {k: v for k, v in detection.items() if k != "condition"}

    def resolve(name: str) -> Selection:
        if name in named_blocks:
            return _block_to_selection(named_blocks[name])
        raise ConversionError(f"condition refers to unknown identifier '{name}'")

    def resolve_wildcard(pattern: str) -> Selection:
        matches = [k for k in named_blocks if fnmatch.fnmatch(k, pattern)]
        if not matches:
            raise ConversionError(f"no selections match wildcard '{pattern}'")
        return [resolve(m) for m in matches]

    cond = condition.lower()

    m = re.match(r"^1\s+of\s+(.+)$", cond)
    if m:
        target = m.group(1).strip()
        if target == "them":
            sels = [resolve(k) for k in named_blocks]
        else:
            sels = resolve_wildcard(target)
        result = sels[0]
        for s in sels[1:]:
            result = _combine_or(result, s)
        return result

    m = re.match(r"^all\s+of\s+(.+)$", cond)
    if m:
        target = m.group(1).strip()
        if target == "them":
            sels = [resolve(k) for k in named_blocks]
        else:
            sels = resolve_wildcard(target)
        result = sels[0]
        for s in sels[1:]:
            result = _combine_and(result, s)
        return result

    def resolve_term(term: str) -> Selection:
        term = term.strip()
        if term.lower().startswith("not "):
            return _negate_selection(resolve(term[4:].strip()))
        return resolve(term)

    # Generic "A and B and ..." / "A or B or ..." with optional 'not ' per term.
    # Mixing 'and' and 'or' in the same condition (without parentheses) is
    # ambiguous and intentionally not supported.
    tokens = re.split(r"\s+(and|or)\s+", condition, flags=re.IGNORECASE)
    if len(tokens) > 1:
        ops = {t.lower() for t in tokens[1::2]}
        if len(ops) > 1:
            raise ConversionError(
                "mixing 'and' and 'or' in one condition without parentheses "
                "is not supported — please simplify the rule"
            )
        op = ops.pop()
        terms = tokens[0::2]
        combine = _combine_and if op == "and" else _combine_or
        result = resolve_term(terms[0])
        for t in terms[1:]:
            result = combine(result, resolve_term(t))
        return result

    # single identifier (possibly 'not <ident>' already handled above)
    return resolve_term(condition)
