import pytest

from daprivacyscanner.expr import ExprError, parse


@pytest.mark.parametrize("src, values, expected", [
    ("device == 'desktop'", {"device": "desktop"}, True),
    ("device == 'desktop'", {"device": "laptop"}, False),
    ("device != 'desktop'", {"device": "laptop"}, True),
    ("hibernation", {"hibernation": True}, True),
    ("not multi_user", {"multi_user": False}, True),
    ("device == 'desktop' and not multi_user", {"device": "desktop", "multi_user": False}, True),
    ("device == 'desktop' and not multi_user", {"device": "desktop", "multi_user": True}, False),
    ("a or b", {"a": False, "b": True}, True),
    ("not (a or b)", {"a": False, "b": False}, True),
    ("a and b or c", {"a": False, "b": True, "c": True}, True),   # and binds tighter than or
    ("x == true", {"x": True}, True),
])
def test_evaluate(src, values, expected):
    assert parse(src).evaluate(values) is expected


@pytest.mark.parametrize("src, values, expected", [
    ("fde == 'none'", {}, None),                          # unknown name
    ("fde == 'none'", {"fde": None}, None),
    ("not autologin", {"autologin": None}, None),
    ("a and b", {"a": False, "b": None}, False),          # decided without b
    ("a and b", {"a": True, "b": None}, None),
    ("a or b", {"a": True, "b": None}, True),
    ("a or b", {"a": False, "b": None}, None),
])
def test_unknown_is_three_valued(src, values, expected):
    assert parse(src).evaluate(values) is expected


def test_names_and_comparisons():
    e = parse("device == 'desktop' and not multi_user")
    assert e.names == {"device", "multi_user"}
    assert e.comparisons() == [("device", "desktop")]


@pytest.mark.parametrize("src", ["", "a ==", "(a", "a b", "a = 'x'", "a == \"x\"", "__import__('os')", "a and"])
def test_rejects(src):
    with pytest.raises(ExprError):
        parse(src)
