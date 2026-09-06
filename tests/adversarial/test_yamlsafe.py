"""Adversarial tests for the strict YAML loader.

A hostile rulebook/config must never be able to: exhaust memory via nested or
wide documents, silently override duplicate keys, or hang consumers with giant
scalars. Each of these cases asserts a loud, bounded failure.
"""

from __future__ import annotations

import pytest

from sentinel.yamlsafe import (
    MAX_DEPTH,
    MAX_DOC_BYTES,
    MAX_KEYS,
    MAX_REFS,
    MAX_SCALAR_LEN,
    YamlSafetyError,
    load_yaml_strict,
)


def test_duplicate_key_rejected():
    with pytest.raises(YamlSafetyError, match="duplicate key"):
        load_yaml_strict("a: 1\na: 2\n")
    with pytest.raises(YamlSafetyError, match="duplicate key"):
        load_yaml_strict("nested:\n  a: 1\n  a: 2\n")
    # duplicate key inside one of the packaged rulebooks would be fatal too
    assert load_yaml_strict("a: 1\nb: 2\n") == {"a": 1, "b": 2}


def test_deep_nesting_rejected():
    deep = "\n".join(f"{'  ' * i}k{i}:" for i in range(MAX_DEPTH + 1))
    with pytest.raises(YamlSafetyError, match="nesting"):
        load_yaml_strict(deep)


def test_giant_scalar_rejected():
    with pytest.raises(YamlSafetyError, match="scalar"):
        load_yaml_strict(f"big: '{'x' * (MAX_SCALAR_LEN + 1)}'")


def test_too_many_keys_rejected():
    keys = "\n".join(f"k{i}: 1" for i in range(MAX_KEYS + 1))
    with pytest.raises(YamlSafetyError):
        load_yaml_strict(keys)


def test_reference_budget_rejected():
    # Ten thousand alias references must trip the reference budget; aliases are
    # memoized by node identity, so this is a fan-out test, not a construction bomb.
    refs = "base: &b {x: 1}\nitems:\n" + "".join("  - *b\n" for _ in range(MAX_REFS + 10))
    with pytest.raises(YamlSafetyError):
        load_yaml_strict(refs)


def test_many_plain_entries_rejected():
    # 12k ordinary scalar pairs, no aliases -> reference budget trips on size.
    many = "\n".join(f"k{i}: v{i}" for i in range(MAX_REFS + 10))
    with pytest.raises(YamlSafetyError):
        load_yaml_strict(many)


def test_huge_document_rejected_before_parse():
    with pytest.raises(YamlSafetyError, match="too large"):
        load_yaml_strict("- a\n" * (MAX_DOC_BYTES // 3 + 1))


def test_anchor_alias_normal_use_still_works():
    data = load_yaml_strict("defaults: &d\n  x: 1\nitem:\n  <<: *d\n  y: 2\n")
    assert data["item"]["x"] == 1
    assert data["item"]["y"] == 2
    # list-of-merges form also works
    data = load_yaml_strict(
        "a: &a {x: 1}\nb: &b {y: 2}\nc:\n  <<: [*a, *b]\n  z: 3\n"
    )
    assert data["c"] == {"x": 1, "y": 2, "z": 3}


def test_bad_syntax_raises_safety_error_not_silent_none():
    with pytest.raises(YamlSafetyError, match="invalid yaml"):
        load_yaml_strict("a: [unclosed")


def test_empty_document_is_none():
    assert load_yaml_strict("") is None


def test_yaml_error_is_safety_error_wrapper():
    # the loader must never leak raw yaml errors as "valid empty data"
    for bad in ("a: &a [*a]", ":\t", "!!python/object:os.system"):
        with pytest.raises(YamlSafetyError):
            load_yaml_strict(bad)