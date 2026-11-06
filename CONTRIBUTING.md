# Contributing

Thanks for considering a contribution to VeilRelay.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest --cov=veilrelay.detectors --cov=veilrelay.models --cov=veilrelay.policy --cov=veilrelay.vault --cov=veilrelay.stream --cov-report=term-missing
ruff check src tests bench
mypy src/veilrelay
bandit -r src
pip-audit
```

For the optional NER layer, install `.[ner]` and install a spaCy model explicitly. For Presidio/public benchmark support, install `.[bench]`.

## Contribution rules

- Keep detector output to offsets, entity type, detector name, and confidence. Never place matched values in `repr`, exceptions, audit events, metrics or debug logs.
- Add positive and false-positive tests for every detector. Use fictional values only.
- Prefer validators/checksums over shape-only detection where the identifier supports them.
- Keep the proxy fail-closed by default; fail-open behavior must remain explicit and noisy.
- Preserve request-scoped vault cleanup and add tests for cancellation/error/TTL paths when changing proxy behavior.
- Do not add telemetry, remote scanning, accounts, or hosted dependencies without a documented design proposal.
- Benchmark changes with the harness and commit raw results. Do not type benchmark numbers into the README.

## Pull requests

Use Conventional Commit-style subjects where practical (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Describe the threat-model impact, tests run, benchmark methodology, and known limitations. Reviewers should be able to reproduce the result from committed source and commands.
