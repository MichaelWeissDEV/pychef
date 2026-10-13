"""Deterministic operation-to-module mapping for lazy loading."""

from __future__ import annotations

import keyword
import re

from .compatibility import UPSTREAM_OPERATION_NAMES


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return f"{slug}_operation" if keyword.iskeyword(slug) else slug


OPERATION_MODULES: dict[str, str] = {name: _slug(name) for name in sorted(UPSTREAM_OPERATION_NAMES)}
MODULES: tuple[str, ...] = tuple(OPERATION_MODULES.values())
