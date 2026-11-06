# Security policy

## Supported versions

Security fixes are developed against the latest released version on the `main` branch. The project is currently alpha (`0.1.x`); no enterprise support or security SLA is offered.

## Reporting a vulnerability

Please do not disclose exploitable issues in public GitHub issues or discussions. Use GitHub's **Private vulnerability reporting / Security Advisories** for this repository when enabled. If private reporting is unavailable, contact a maintainer through the contact details published on the repository owner's GitHub profile and request a private channel.

Include the affected version/commit, impact, a minimal reproduction, and any relevant environment assumptions. Do not include real PII or live credentials in the report; use synthetic examples. The maintainers will acknowledge receipt, assess severity, coordinate a fix, and agree on disclosure timing with the reporter.

## Scope

In-scope issues include bypasses of the documented detection/policy flow, raw-value leakage into logs or files, vault isolation/expiry defects, upstream allowlist bypasses, request-limit bypasses, and vulnerabilities in the supported proxy endpoints.

Out of scope by design: detection of deliberate encoding/obfuscation, host compromise, provider compromise or provider-side retention, unsupported multimodal/file routes, and false negatives for unsupported identifier formats. These are limitations, not security guarantees.

## Safe testing

Use only synthetic test values and a local mock upstream. Never send live credentials, personal identifiers, production prompts, or third-party data to test deployments. Do not run denial-of-service or intrusive tests against systems you do not own.
