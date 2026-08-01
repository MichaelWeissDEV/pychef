"""Sphinx configuration for the PyChef documentation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pychef  # noqa: E402

project = "PyChef"
author = "Michael Weiss"
copyright = "2026, Michael Weiss"
version = pychef.__version__
release = pychef.__version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx_copybutton",
]

root_doc = "index"
source_suffix = ".rst"
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_static_path = ["_static"]
html_css_files = ["custom.css"]

html_theme = "sphinx_rtd_theme"
html_title = f"PyChef {release} documentation"
html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 4,
    "sticky_navigation": True,
}

autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_preserve_defaults = True
autodoc_type_aliases = {
    "OperationRegistry": "pychef.registry.OperationRegistry",
}
autosummary_generate = False
napoleon_google_docstring = True
napoleon_numpy_docstring = False
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True

html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "")
if os.environ.get("READTHEDOCS") == "True":
    html_context = {
        "READTHEDOCS": True,
        "current_version": os.environ.get("READTHEDOCS_VERSION", "latest"),
        "version_slug": os.environ.get("READTHEDOCS_VERSION", "latest"),
    }
