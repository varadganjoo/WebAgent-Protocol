# Contributing

Thanks for helping build an open, safe agentic web. Bug reports, protocol feedback and pull requests are all welcome.

## Development setup

```bash
git clone https://github.com/varadganjoo/WebAgent-Protocol
cd WebAgent-Protocol
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check . && ruff format --check .   # lint + formatting
pytest -q                               # full suite, runs in-process in a few seconds
```

- Add tests for behaviour changes. Security-relevant code (signatures, proof-of-work, rate limits, loop
  protection, resolution) needs adversarial tests, not just happy paths.
- Protocol changes must update [`docs/spec_rfc.md`](docs/spec_rfc.md) (and
  [`docs/mcp_extension.md`](docs/mcp_extension.md) if they touch the MCP binding) in the same pull request.
- Note user-visible changes under an "Unreleased" heading in [`CHANGELOG.md`](CHANGELOG.md).
- Keep the core package dependency-light: FastAPI and MCP belong to the `server` / `mcp` extras.

## Proposing protocol changes

Open an issue describing the problem first. Good proposals explain the threat or use case, the wire-format
change, backward compatibility, and how a minimal implementation in another language would do it.

## Releasing (maintainers)

Releases are published to PyPI by `.github/workflows/release.yml` using
[trusted publishing](https://docs.pypi.org/trusted-publishers/), so no API token is stored in the repository.

One-time setup on PyPI: add a (pending) trusted publisher for project `webagent-protocol` with owner
`varadganjoo`, repository `WebAgent-Protocol`, workflow `release.yml`, environment `pypi`.

To release:

1. Bump `__version__` in `wap/__init__.py` and move "Unreleased" notes in `CHANGELOG.md` under the new version.
2. Merge to `main`, then create a GitHub release with tag `vX.Y.Z`.
3. The workflow runs the tests, builds the sdist and wheel, checks the tag matches the version, and publishes.
