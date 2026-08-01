# Releasing

The distribution name is `py-chef`; users import it as `pychef`. Releases
are built with uv and published through PyPI Trusted Publishing. No persistent
PyPI token is required.

## One-time setup

Create the GitHub environments `testpypi` and `pypi`. Require a reviewer for
the `pypi` environment.

Register pending Trusted Publishers with these exact values:

| Registry | Project | Owner | Repository | Workflow | Environment |
|---|---|---|---|---|---|
| TestPyPI | `py-chef` | `MichaelWeissDEV` | `pychef` | `test-publish.yml` | `testpypi` |
| PyPI | `py-chef` | `MichaelWeissDEV` | `pychef` | `publish.yml` | `pypi` |

Pending publishers can create the projects on first upload. Recheck that the
name is still available immediately before the first release.

## Prepare a release

1. Ensure the worktree is clean and the full CI workflow passes.
2. Update `CHANGELOG.md` and choose the version:

   ```console
   uv version 0.1.0
   ```

3. Validate locally:

   ```console
   uv sync --locked --dev
   uv run ruff format --check .
   uv run ruff check .
   uv run ty check
   uv run pytest
   uv build --no-sources --clear
   uv run twine check --strict dist/*
   uv run check-wheel-contents dist/*.whl
   uv run --isolated --no-project --with dist/*.whl tests/smoke_test.py
   uv run --isolated --no-project --with dist/*.tar.gz tests/smoke_test.py
   ```

4. Commit the version and changelog.
5. Run the `Publish to TestPyPI` workflow manually and test installation from
   TestPyPI.
6. Create an annotated tag matching the package version and push it:

   ```console
   git tag -a v0.1.0 -m "PyChef 0.1.0"
   git push origin v0.1.0
   ```

7. Create a GitHub release from that tag. Publishing the release triggers the
   `Publish to PyPI` workflow after its environment approval.

PyPI does not permit replacing files for an existing version. If a release is
incorrect, increment the version and publish a new release.
