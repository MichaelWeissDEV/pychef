"""CyberChef RAKE keyword extraction examples."""

from __future__ import annotations

from pychef import bake


def test_rake_official_basic_example() -> None:
    assert bake(
        "test1 test2. test2",
        [{"op": "RAKE", "args": [r"\s", r"\.\s|\n", "i,me,my,myself,we,our"]}],
    ) == "Scores: , Keywords: \n3.5, test1 test2\n1.5, test2"


def test_rake_custom_delimiters_stop_words_and_deduplication() -> None:
    result = bake(
        "Alpha,Beta! alpha,beta! alpha and gamma",
        [{"op": "RAKE", "args": [",|\\s", "!\\s*", "and"]}],
    )
    assert isinstance(result, str)
    assert result.startswith("Scores: , Keywords: \n")
    assert result.count("alpha beta") == 1
    assert "gamma" in result
