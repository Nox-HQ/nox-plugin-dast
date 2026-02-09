# nox-plugin-dast

DAST Web/API Scanner plugin for the [Nox](https://github.com/nox-hq/nox) security scanner.

## Description

`nox-plugin-dast` performs static detection of web and API security misconfigurations in server-side code. It identifies missing security headers, insecure CORS configurations, TLS enforcement gaps, cookie security issues, missing rate limiting, and open redirect vulnerabilities.

## Track

**Dynamic & Runtime** -- active risk class, requires confirmation. Analyzes code patterns that indicate dynamic/runtime security issues.

## Supported Languages

- Go (.go)
- Python (.py)
- JavaScript (.js)
- TypeScript (.ts)

## Rules

| Rule ID  | Description                         | Severity | Confidence | CWE     |
|----------|-------------------------------------|----------|------------|---------|
| DAST-001 | Missing security headers            | HIGH     | HIGH       | CWE-693 |
| DAST-002 | Insecure CORS configuration         | HIGH     | MEDIUM     | CWE-942 |
| DAST-003 | Missing TLS/HTTPS enforcement       | MEDIUM   | HIGH       | CWE-319 |
| DAST-004 | Insecure cookie settings            | HIGH     | MEDIUM     | CWE-614 |
| DAST-005 | Missing rate limiting on API        | MEDIUM   | MEDIUM     | CWE-770 |
| DAST-006 | Open redirect patterns              | HIGH     | HIGH       | CWE-601 |

## Installation

```bash
nox plugin install nox-hq/nox-plugin-dast
```

## Usage

```bash
# Run via Nox
nox scan --plugin nox/dast .

# Run standalone
nox-plugin-dast
```

## Development

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# Clean build artifacts
make clean
```

## License

Apache-2.0
