"""Safe, standard-library XML XPath and small CSS selector operations."""

from __future__ import annotations

import re
import xml.etree.ElementTree as element_tree

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg, char_rep


def _serialize(elements: list[element_tree.Element], delimiter: str) -> str:
    serialized: list[str] = []
    for element in elements:
        tail = element.tail
        element.tail = None
        try:
            serialized.append(
                element_tree.tostring(element, encoding="unicode", short_empty_elements=True)
            )
        finally:
            element.tail = tail
    return delimiter.join(serialized)


def _delimiter(value: object) -> str:
    return char_rep(value, "\n").replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t")


def _simple_selector_matches(element: element_tree.Element, selector: str) -> bool:
    match = re.fullmatch(r"([A-Za-z][\w:-]*)?(?:#([\w:-]+))?(?:\.([\w:-]+))?", selector)
    if not match:
        raise ValueError(f"unsupported CSS selector component: {selector}")
    tag, element_id, class_name = match.groups()
    classes = element.attrib.get("class", "").split()
    return (
        (tag is None or element.tag == tag)
        and (element_id is None or element.attrib.get("id") == element_id)
        and (class_name is None or class_name in classes)
    )


@operation("CSS selector", category="Code")
def css_selector(value: Data, args: Args) -> str:
    selector = str(arg(args, 0, "")).strip()
    delimiter = _delimiter(arg(args, 1, "Line feed"))
    if not selector:
        return ""
    root = element_tree.fromstring(to_text(value))
    parts = selector.split()
    matches: list[element_tree.Element] = []

    def visit(element: element_tree.Element, ancestors: tuple[element_tree.Element, ...]) -> None:
        if _simple_selector_matches(element, parts[-1]):
            cursor = len(ancestors) - 1
            for component in reversed(parts[:-1]):
                while cursor >= 0 and not _simple_selector_matches(ancestors[cursor], component):
                    cursor -= 1
                if cursor < 0:
                    break
                cursor -= 1
            else:
                matches.append(element)
        for child in element:
            visit(child, (*ancestors, element))

    visit(root, ())
    return _serialize(matches, delimiter)


@operation("XPath expression", category="Code")
def xpath_expression(value: Data, args: Args) -> str:
    expression = str(arg(args, 0, "")).strip()
    delimiter = _delimiter(arg(args, 1, "Line feed"))
    if not expression:
        return ""
    root = element_tree.fromstring(to_text(value))
    root_prefix = f"/{root.tag}"
    if expression == root_prefix:
        matches = [root]
    elif expression.startswith(root_prefix + "/"):
        matches = root.findall("." + expression[len(root_prefix) :])
    elif expression.startswith("/"):
        matches = root.findall("." + expression)
    else:
        matches = root.findall(expression)
    return _serialize(matches, delimiter)
