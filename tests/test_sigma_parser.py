import pytest

from sigma2wazuh.sigma_parser import SigmaParseError, load_sigma_rule

EXAMPLES = "examples"


def test_load_valid_rule():
    rule = load_sigma_rule(f"{EXAMPLES}/suspicious_powershell_download.yml")
    assert rule.title == "Suspicious PowerShell Download Command"
    assert rule.level == "high"
    assert "selection" in rule.detection
    assert rule.detection["condition"] == "selection"


def test_mitre_ids_extracted():
    rule = load_sigma_rule(f"{EXAMPLES}/suspicious_lsass_access.yml")
    assert rule.mitre_ids == ["T1003.001"]


def test_missing_required_field(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: Missing stuff\n")
    with pytest.raises(SigmaParseError):
        load_sigma_rule(bad)


def test_missing_condition(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "title: X\nlogsource: {product: windows}\ndetection:\n  selection:\n    Image: foo\n"
    )
    with pytest.raises(SigmaParseError):
        load_sigma_rule(bad)


def test_invalid_yaml(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n")
    with pytest.raises(SigmaParseError):
        load_sigma_rule(bad)
