# Security policy

## Supported versions

Security fixes are applied to the latest tagged release and the `main` branch.

## Reporting a vulnerability

Please use GitHub's private security-advisory feature instead of opening a public issue. Include the affected version, a minimal reproduction and the impact. Do not include real credentials, customer logs or personal data.

## Security boundaries

TraceForge runs offline and has no network client. It redacts common credential forms before events enter the report model, refuses malformed JSON records, limits line and event counts, avoids overwriting non-empty output directories and verifies bundle artifacts with SHA-256.

TraceForge does not claim to discover every sensitive-data format. Review generated reports before sharing them. SHA-256 manifests are tamper-evident, not a digital signature and not a substitute for a formal forensic chain-of-custody process.
