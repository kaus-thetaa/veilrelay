# Commit and test log

Commits were authored locally using Conventional Commit subjects. For the implementation commits, the full test suite was run immediately after each commit; all those runs were green. The bootstrap commits predated the test suite and are marked accordingly.

| Commit | Message | Test status after commit |
|---|---|---|
| `9ceb07d` | `chore: init repo with MIT license and Python project metadata` | Bootstrap only; test suite not yet added |
| `d586b65` | `docs: add threat model and project scope` | Docs-only bootstrap; test suite not yet added |
| `8bb537b` | `feat(core): add span models and pluggable detector interfaces` | 76 passed, 1 skipped |
| `8c31794` | `feat(detectors): add validated PII patterns and Indian identifiers` | 76 passed, 1 skipped |
| `a7aba0f` | `feat(secrets): detect provider tokens and private credential material` | 76 passed, 1 skipped |
| `42a7028` | `test(detectors): add false-positive traps and negative cases` | 76 passed, 1 skipped |
| `10d3c80` | `feat(vault): add in-memory reversible token vault with TTL` | 76 passed, 1 skipped |
| `5935328` | `test(vault): add Hypothesis round-trip and mapping properties` | 76 passed, 1 skipped |
| `1ebbc84` | `feat(policy): add YAML actions allowlists and custom rules` | 76 passed, 1 skipped |
| `b3b5add` | `feat(stream): add boundary-safe plain-text and SSE restoration` | 76 passed, 1 skipped |
| `9a3c0b9` | `feat(audit): write value-free JSONL request events` | 76 passed, 1 skipped |
| `56073d6` | `feat(proxy): add OpenAI-compatible chat and model passthrough` | 76 passed, 1 skipped |
| `ff624f9` | `feat(cli): add serve scan and benchmark commands` | 76 passed, 1 skipped |
| `9b27114` | `feat(ner): add opt-in spaCy named-entity detection` | 76 passed, 1 skipped |
| `b7155ab` | `build(package): pin setuptools build and runtime dependencies` | 76 passed, 1 skipped |
| `889647b` | `chore(security): add operator config and value-free repository scanner` | 76 passed, 1 skipped |
| `8430712` | `ci: add tests lint type and dependency security workflows` | 76 passed, 1 skipped |
| `d51690c` | `build(docker): add hardened container and compose deployment` | 76 passed, 1 skipped |
| `0a2c905` | `bench: add synthetic corpus and licensed OpenPII adapter` | 76 passed, 1 skipped |
| `2c37997` | `bench: add detector metrics latency and utility harness` | 76 passed, 1 skipped |
| `5ee50ed` | `bench: commit measured smoke results and generated report tables` | 76 passed, 1 skipped |
| `a906070` | `test(stream): cover SSE control frames and fallback paths` | 79 passed, 1 skipped |

The single skipped module is `tests/test_properties.py`, because Hypothesis was unavailable locally. The dev dependency and CI installation are configured to run it in CI. The final coverage run measured 92.09% across the configured core modules.
| `b7ae370` | `docs: publish benchmark-backed README and quickstart` | 79 passed, 1 skipped |
| `2de6d66` | `docs(launch): add simulated demo and community launch drafts` | 79 passed, 1 skipped |
| `1858c0c` | `docs: add contributor security and release guidance` | 79 passed, 1 skipped |
