"""Rapid Automatic Keyword Extraction compatible with CyberChef's RAKE operation."""

from __future__ import annotations

import re
from typing import TypeVar

from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg

_DEFAULT_STOP_WORDS = "i,me,my,myself,we,our"
_T = TypeVar("_T")


def _unique(values: list[_T]) -> list[_T]:
    output: list[_T] = []
    for value in values:
        if value not in output:
            output.append(value)
    return output


@implementation("RAKE", category="Analysis")
def rake(value: Data, args: Args) -> Data:
    word_delimiter = re.compile(str(arg(args, 0, r"\s")))
    sentence_delimiter = re.compile(str(arg(args, 1, r"\.\s|\n")))
    stop_words = _unique(str(arg(args, 2, _DEFAULT_STOP_WORDS)).lower().replace(" ", "").split(","))
    stop_words.append("")
    text = to_text(value).lower().strip()
    tokens: list[str] = []
    frequencies: list[int] = []
    phrases: list[list[str]] = []
    for sentence in sentence_delimiter.split(text):
        words = word_delimiter.split(sentence)
        start = 0
        for index, token in enumerate(words):
            if token in stop_words:
                phrases.append(words[start:index])
                start = index + 1
            elif token in tokens:
                frequencies[tokens.index(token)] += 1
            else:
                tokens.append(token)
                frequencies.append(1)
        phrases.append(words[start:])
    phrases = _unique([phrase for phrase in phrases if phrase])
    degree_matrix = [[0] * len(tokens) for _ in tokens]
    for phrase in phrases:
        for first in phrase:
            for second in phrase:
                degree_matrix[tokens.index(first)][tokens.index(second)] += 1
    degree_scores = [
        sum(degree_matrix[row][index] for row in range(len(tokens))) / frequencies[index]
        for index in range(len(tokens))
    ]
    scores = [
        (sum(degree_scores[tokens.index(token)] for token in phrase), " ".join(phrase))
        for phrase in phrases
    ]
    scores.sort(key=lambda item: item[0], reverse=True)
    lines = ["Scores: , Keywords: "]
    for score, phrase in scores:
        rendered = str(int(score)) if score == int(score) else str(score)
        lines.append(f"{rendered}, {phrase}")
    return "\n".join(lines)
