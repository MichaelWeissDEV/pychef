"""Official CyberChef selector vectors."""

from __future__ import annotations

from pychef import bake

_DOCUMENT = '<div id="test">\n<p class="a">hello</p>\n<p>world</p>\n<p class="a">again</p>\n</div>'
_EXPECTED = '<p class="a">hello</p>\n<p class="a">again</p>'


def test_css_selector_official_vector() -> None:
    assert bake(_DOCUMENT, [{"op": "CSS selector", "args": ["#test p.a", "\\n"]}]) == (_EXPECTED)


def test_xpath_expression_official_vector() -> None:
    assert (
        bake(
            _DOCUMENT,
            [{"op": "XPath expression", "args": ['/div/p[@class="a"]', "\\n"]}],
        )
        == _EXPECTED
    )
