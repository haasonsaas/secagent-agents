# secagent Benchmarks

This folder contains intentionally vulnerable fixtures for regression testing detector/manager behavior over time.

## Fixtures

- `fixtures/python_idor`: minimal Flask-style endpoint with missing ownership checks.

## Usage

Run secagent against a fixture with a profile and compare report outputs over time:

```bash
uv run secagent --repo benchmarks/fixtures/python_idor --profile general --out benchmark_report.json
```

Use these fixtures when changing prompts/profiles to ensure findings do not silently regress.
