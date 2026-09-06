"""Strict, resource-bounded YAML loading for untrusted rulebooks and configs.

Standard ``yaml.safe_load`` refuses arbitrary Python tags, but a hostile file
can still:
  * hide duplicate keys (last-wins) that silently change rule semantics,
  * hold giant scalars / absurdly wide or deep documents (memory DoS),
  * compose anchor/alias-heavy documents that cost time per reference.

Note: PyYAML 6.x composes anchors/aliases into *shared node objects* and
memoizes construction by node identity, so a classic "billion laughs" does not
reconstruct fresh data per alias. What remains unbounded is reference fan-out,
which is what the per-reference budget here bounds.

This module layers hard bounds on top of the safe loader and raises
``YamlSafetyError`` for anything outside them.  No keyboard-defined types are
ever constructed.
"""

from __future__ import annotations

from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_DEPTH = 100           # nesting depth of the composed tree
MAX_SCALAR_LEN = 200_000  # a single scalar string
MAX_KEYS = 5_000          # keys in one mapping
MAX_REFS = 10_000         # total construct_object calls (covers distinct nodes too)

MAX_DOC_BYTES = 4 * 1024 * 1024


__all__: list[str] = ["YamlSafetyError", "load_yaml_strict"]


class YamlSafetyError(ValueError):
    pass


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys and over-budget docs."""

    _refs = 0

    def construct_object(self, node, deep=False):
        self._refs += 1
        if self._refs > MAX_REFS:
            raise ConstructorError(None, None, f"yaml exceeds {MAX_REFS} reference budget")
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None, None, "expected a mapping node", node.start_mark)
        if len(node.value) > MAX_KEYS:
            raise ConstructorError(
                None, None, f"yaml mapping has >{MAX_KEYS} keys")
        # Duplicate-key check on the raw pairs (merge-key entries are exempt —
        # they are handled by flatten_mapping below).
        seen: set = set()
        for key_node, _value_node in node.value:
            if key_node.value == "<<":
                continue
            key = self.construct_object(key_node, deep=True)
            try:
                if key in seen:
                    raise ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        f"found duplicate key {key!r}", key_node.start_mark)
                seen.add(key)
            except TypeError:
                pass  # unhashable key -> identity semantics, no dup possible
        self.flatten_mapping(node)  # apply << merges (kept within node budgets)
        mapping: dict = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _type_check_and_limit(text: str) -> None:
    if len(text) > MAX_DOC_BYTES:
        raise YamlSafetyError(
            f"yaml document too large ({len(text)} bytes > {MAX_DOC_BYTES})")
    # Walk the composed tree once (no construction) to enforce depth/scalars.
    loader = _StrictSafeLoader(text)
    try:
        max_depth = 0

        def walk(node: Node | None, d: int) -> None:
            nonlocal max_depth
            if node is None:
                return
            max_depth = max(max_depth, d)
            if d > MAX_DEPTH:
                raise YamlSafetyError(f"yaml nesting deeper than {MAX_DEPTH}")
            if isinstance(node, ScalarNode):
                if node.value and len(node.value) > MAX_SCALAR_LEN:
                    raise YamlSafetyError(
                        f"yaml scalar longer than {MAX_SCALAR_LEN} chars")
            elif isinstance(node, SequenceNode):
                if len(node.value) > MAX_KEYS:
                    raise YamlSafetyError(
                        f"yaml sequence has >{MAX_KEYS} items")
                for child in node.value:
                    walk(child, d + 1)
            elif isinstance(node, MappingNode):
                if len(node.value) > MAX_KEYS:
                    raise YamlSafetyError(
                        f"yaml mapping has >{MAX_KEYS} keys")
                for k, v in node.value:
                    walk(k, d + 1)
                    walk(v, d + 1)

        root = loader.get_single_node()
        walk(root, 0)
    except yaml.YAMLError:
        pass  # underlying loader will surface parse errors on construction
    finally:
        loader.dispose()


def load_yaml_strict(text: str) -> Any:
    """Parse ``text`` with duplicate-key and resource-limit enforcement."""
    _type_check_and_limit(text)
    loader = _StrictSafeLoader(text)
    try:
        return loader.get_single_data()
    except ConstructorError as exc:
        raise YamlSafetyError(str(exc)) from exc
    except yaml.YAMLError as exc:
        raise YamlSafetyError(f"invalid yaml: {exc}") from exc
    finally:
        loader.dispose()