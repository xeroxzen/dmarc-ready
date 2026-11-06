# Contributing

Thanks for helping. Bug reports, parser fixes for reports that don't load, and documentation fixes are all welcome.

## Set up

```bash
git clone https://github.com/xeroxzen/dmarc-ready.git
cd dmarc-ready
uv sync
```

## A report that won't load

Receivers format reports in slightly different ways. If one is skipped, open an issue with the error message and the reporting organisation's name. If you attach a sample, replace the IP addresses with ones from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and the domains with `example.com`.

## Before you open a pull request

All of these must pass with no warnings:

```bash
uv run pytest
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
```

Also:

- Add a test that fails without your change. Build reports with `tests/helpers.py` rather than committing real ones.
- Record the change in the [changelog](CHANGELOG.md).
