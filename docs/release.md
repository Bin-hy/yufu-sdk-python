# Release to PyPI

The package is published as `yufu-sdk` with PyPI Trusted Publishing. No API
token is stored in the repository.

## One-time PyPI setup

1. Create the `yufu-sdk` project on PyPI.
2. Open the project's **Publishing** settings and add a Trusted Publisher:
   - Owner: `Bin-hy`
   - Repository: `yufu-sdk-python`
   - Workflow: `publish.yml`
   - Environment: `pypi`
3. In GitHub, create an environment named `pypi` under
   **Settings → Environments**. Add required reviewers if the release should be
   manually approved.

## Versioning

The package version lives in `src/yufu/_version.py` and is read by Hatchling.
It follows SemVer independently of the yufu server.

Before a release:

1. Update `__version__`.
2. Run the full local gate:

   ```bash
   ruff check .
   ruff format --check .
   mypy src tests
   YUFU_CONTRACT_FIXTURES=/path/to/yufu/sdk/contract-fixtures pytest
   python -m build
   twine check dist/*
   ```

3. Commit the version bump and push it to `main`.
4. Tag and push:

   ```bash
   git tag v0.1.1
   git push origin v0.1.1
   ```

PyPI versions are immutable. Never re-tag a version that was already published;
bump `__version__`, commit, and create a new tag instead.

The `Publish` workflow builds the sdist and wheel, checks the metadata, and
publishes through OIDC. The GitHub environment approval, when configured, is
the final release gate.

## Contract fixture provenance

CI checks out `Bin-hy/yufu@main` and runs the shared fixtures from
`sdk/contract-fixtures`. Record the fixture `manifest.version` and the yufu
commit SHA in the GitHub release notes so consumers can correlate an SDK
release with the protocol corpus it was tested against.

## TestPyPI (optional)

To rehearse a release, add a separate `testpypi` environment and a manual
workflow step using:

```yaml
- uses: pypa/gh-action-pypi-publish@release/v1
  with:
    repository-url: https://test.pypi.org/legacy/
```

TestPyPI does not allow overwriting an existing version, so use a pre-release
version such as `0.1.0rc1` for the rehearsal.
