import xml.etree.ElementTree as ET

from sigma2wazuh.converter import convert_directory, convert_file

EXAMPLES = "examples"


def test_convert_single_file_produces_valid_xml():
    xml_text, warnings = convert_file(f"{EXAMPLES}/suspicious_powershell_download.yml")
    assert warnings == []
    root = ET.fromstring(xml_text)  # raises if not well-formed
    assert root.tag == "group"
    rules = root.findall("rule")
    assert len(rules) == 1
    rule = rules[0]
    assert rule.get("level") == "12"
    fields = rule.findall("field")
    assert len(fields) == 2
    desc = rule.find("description").text
    assert "Suspicious PowerShell Download Command" in desc
    mitre_ids = [e.text for e in rule.findall("mitre/id")]
    assert mitre_ids == ["T1059.001"]


def test_convert_and_not_filter_sets_negate_attribute():
    xml_text, _warnings = convert_file(f"{EXAMPLES}/suspicious_lsass_access.yml")
    root = ET.fromstring(xml_text)
    rule = root.find("rule")
    negated_fields = [f for f in rule.findall("field") if f.get("negate") == "yes"]
    assert len(negated_fields) == 1


def test_convert_or_condition_produces_two_rules_with_warning():
    xml_text, warnings = convert_file(f"{EXAMPLES}/suspicious_scheduled_task_or_service.yml")
    assert len(warnings) == 1
    root = ET.fromstring(xml_text)
    rules = root.findall("rule")
    assert len(rules) == 2
    ids = sorted(int(r.get("id")) for r in rules)
    assert ids[1] == ids[0] + 1


def test_convert_list_style_selection_produces_two_rules():
    xml_text, warnings = convert_file(f"{EXAMPLES}/suspicious_rundll32_variants.yml")
    assert len(warnings) == 1
    root = ET.fromstring(xml_text)
    rules = root.findall("rule")
    assert len(rules) == 2
    for rule in rules:
        assert len(rule.findall("field")) == 2


def test_convert_directory_allocates_unique_sequential_ids():
    xml_text, warnings, errors = convert_directory(EXAMPLES, start_id=200000)
    assert errors == []
    root = ET.fromstring(xml_text)
    ids = [int(r.get("id")) for r in root.findall("rule")]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))  # all unique
    assert ids[0] == 200000
