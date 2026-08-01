# Contributing

Contributions should include tests for every behavior change and retain the
package's Python-only runtime.

## Development setup

Install Python 3.10 or newer and uv, then create the development environment:

```console
uv sync --locked --dev
```

Run the complete local quality gate before opening a pull request:

```console
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
uv build --no-sources --clear
uv run twine check --strict dist/*
uv run check-wheel-contents dist/*.whl
```

Keep public APIs typed and document user-visible changes in `CHANGELOG.md`.
New CyberChef compatibility behavior should be covered by an official upstream
vector or an independent published specification whenever possible.

## Licensing

By submitting a contribution, you agree that it is licensed under the Apache
License 2.0. Preserve applicable upstream attribution and add any new required
notices to `THIRD_PARTY_LICENSES.md`.
