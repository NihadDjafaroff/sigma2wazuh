import pytest

from sigma2wazuh.detection import ConversionError, detection_to_selection

WINDOWS = {"product": "windows"}  # unused, kept for readability of test intent


def test_single_selection_and_of_fields():
    detection = {
        "selection": {
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": ["DownloadString", "IEX"],
        },
        "condition": "selection",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 1  # one AND-group (no OR at top level)
    leaves = sel[0]
    assert len(leaves) == 2
    fields = {leaf.sigma_field for leaf in leaves}
    assert fields == {"Image", "CommandLine"}


def test_and_not_filter():
    detection = {
        "selection": {"TargetImage|endswith": "\\lsass.exe"},
        "filter": {"Image|endswith": "\\werfault.exe"},
        "condition": "selection and not filter",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 1
    leaves = sel[0]
    assert len(leaves) == 2
    negated = [leaf for leaf in leaves if leaf.negate]
    assert len(negated) == 1
    assert negated[0].sigma_field == "Image"


def test_or_produces_multiple_groups():
    detection = {
        "a": {"Image|endswith": "\\schtasks.exe"},
        "b": {"Image|endswith": "\\sc.exe"},
        "condition": "a or b",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 2


def test_list_style_selection_is_or_of_and():
    detection = {
        "selection": [
            {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "JSRunAction"},
            {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "Control_RunDLL"},
        ],
        "condition": "selection",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 2
    for group in sel:
        assert len(group) == 2


def test_all_modifier_requires_every_value():
    detection = {
        "selection": {"CommandLine|contains|all": ["foo", "bar"]},
        "condition": "selection",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 1
    # 'all' expands into one Leaf per value, ANDed within the single group
    assert len(sel[0]) == 2


def test_unknown_identifier_raises():
    detection = {"selection": {"Image": "x"}, "condition": "nonexistent"}
    with pytest.raises(ConversionError):
        detection_to_selection(detection)


def test_not_on_multi_field_selection_raises():
    detection = {
        "selection": {"Image": "x", "User": "y"},
        "condition": "not selection",
    }
    with pytest.raises(ConversionError):
        detection_to_selection(detection)


def test_mixed_and_or_without_parens_raises():
    detection = {
        "a": {"Image": "x"},
        "b": {"Image": "y"},
        "c": {"Image": "z"},
        "condition": "a and b or c",
    }
    with pytest.raises(ConversionError):
        detection_to_selection(detection)


def test_unsupported_modifier_raises():
    detection = {
        "selection": {"Image|basename": "x"},
        "condition": "selection",
    }
    with pytest.raises(ConversionError):
        detection_to_selection(detection)


def test_1_of_them():
    detection = {
        "a": {"Image": "x"},
        "b": {"Image": "y"},
        "condition": "1 of them",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 2


def test_all_of_wildcard():
    detection = {
        "sel_1": {"Image": "x"},
        "sel_2": {"User": "y"},
        "condition": "all of sel_*",
    }
    sel = detection_to_selection(detection)
    assert len(sel) == 1
    assert len(sel[0]) == 2
