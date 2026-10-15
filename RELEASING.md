# Releasing

The distribution name is `cyberchef-py`; users import it as `pychef`. Releases
are built with uv and published through PyPI Trusted Publishing. No persistent
PyPI token is required.

## One-time setup

Create the GitHub environments `testpypi` and `pypi`. Require a reviewer for
the `pypi` environment.

Register pending Trusted Publishers with these exact values:

| Registry | Project | Owner | Repository | Workflow | Environment |
|---|---|---|---|---|---|
| TestPyPI | `cyberchef-py` | `MichaelWeissDEV` | `pychef` | `test-publish.yml` | `testpypi` |
| PyPI | `cyberchef-py` | `MichaelWeissDEV` | `pychef` | `publish.yml` | `pypi` |

Pending publishers can create the projects on first upload. Recheck that the
name is still available immediately before the first release.

## Prepare a release

Nothing below publishes anything until step 9. Steps 1-8 only touch the local
checkout.

1. **Choose the version.** Compare the changes with the last *published* version
   on PyPI (not with internal commit messages) and apply Semantic Versioning:
   new backwards-compatible API -> minor, fixes only -> patch, breaking -> major
   (while `0.x`, breaking changes also bump the minor version). Never reuse a
   version that already exists on PyPI or TestPyPI.

   ```console
   uv version X.Y.Z        # updates pyproject.toml and uv.lock
   uv lock --check
   ```

2. **Prepare the changelog.** Move the `[Unreleased]` entries of `CHANGELOG.md`
   under `## [X.Y.Z] - YYYY-MM-DD` and keep an empty `[Unreleased]` section.
3. **Run the checks** (same commands as CI):

   ```console
   uv sync --locked --dev
   uv run pytest
   uv run ruff check . && uv run ruff format --check .
   uv run ty check
   uv run validate-pyproject pyproject.toml
   ```

4. **Build and validate metadata:**

   ```console
   uv build --no-sources --clear
   uv run twine check --strict dist/*
   uv run check-wheel-contents dist/*.whl
   ```

5. **Install the wheel in isolation** and run the smoke and typing checks (the
   repository must not be importable, so run from a different directory):

   ```console
   uv run --isolated --no-project --with dist/*.whl python tests/smoke_test.py
   uv run python tests/check_wheel_typing.py dist/*.whl
   ```

6. **Install the source distribution in isolation:**

   ```console
   uv run --isolated --no-project --with dist/*.tar.gz python tests/smoke_test.py
   ```

7. **Build the documentation and examples:**

   ```console
   uv sync --locked --group docs
   uv run python docs/_scripts/generate_operation_docs.py --check
   uv run sphinx-build -W --keep-going -b html docs docs/_build/html
   uv run python examples/quickstart.py
   ```

8. **Release candidate review.** Commit the version and changelog on a branch,
   open a pull request, and let the full CI matrix (Linux, macOS, Windows) pass.
   Confirm that the documentation builds for the new version.
9. **Only after explicit approval:** run the `Publish to TestPyPI` workflow
   manually and test installation from TestPyPI in a clean environment:

   ```console
   python -m pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ cyberchef-py==X.Y.Z
   python -c "import pychef; print(pychef.__version__)"
   ```

10. Create an annotated tag matching the package version and push it. Pushing a tag
    `vMAJOR.MINOR.PATCH` starts the `Publish to PyPI` workflow, which checks that the tag
    equals `v<package version>`, that the version is not yet on PyPI and that the built
    artifact names carry that version, then publishes after its environment approval.
    Afterwards create a GitHub release from the same tag for the release notes
    (publishing the release does not publish to PyPI).

    ```console
    git tag -a vX.Y.Z -m "PyChef X.Y.Z"
    git push origin vX.Y.Z
    ```

PyPI does not permit replacing files for an existing version. If a release is
incorrect, increment the version and publish a new release.

## Documentation versions

Read the Docs builds `latest` from `main` (development), `stable` from the newest
release tag, and one permanent version per tag (`v0.2.0`). In the Read the Docs project:
activate new `v*` tags (enable "automation rules" for tags, or activate manually under
Versions), keep `stable` pointing at the newest release, set the default version to
`stable`, and enable "build pull requests". After retagging, trigger a rebuild of the
tag version and confirm that `/en/vX.Y.Z/` shows the expected version in its title.
Never link `latest` pages from release notes; use `/en/vX.Y.Z/` URLs.
