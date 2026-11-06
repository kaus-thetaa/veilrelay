## Summary

## Security / privacy impact

- [ ] No matched values are added to logs, exceptions, metrics, or test output.
- [ ] Fail-closed behavior is preserved unless explicitly justified.
- [ ] Request-scoped vault cleanup and TTL behavior are preserved.
- [ ] Only synthetic test values are used.

## Validation

- [ ] `pytest`
- [ ] `ruff check src tests bench`
- [ ] `mypy src/veilrelay`
- [ ] `bandit -r src`
- [ ] `pip-audit`
- [ ] Benchmark raw results updated if detection/performance changed.

## Known limitations
