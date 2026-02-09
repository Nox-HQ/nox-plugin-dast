# nox-plugin-dast

**DAST web/API security scanning for server-side code.**

## Overview

`nox-plugin-dast` performs static detection of web and API security misconfigurations in server-side source code. Rather than requiring a running application, it identifies code patterns that would lead to exploitable security issues at runtime -- missing security headers, insecure CORS policies, TLS enforcement gaps, cookie misconfigurations, absent rate limiting, and open redirect vulnerabilities.

This plugin bridges the gap between traditional SAST (which focuses on code-level bugs) and runtime DAST tools (which require a deployed application). By detecting DAST-class issues directly in source code during development, teams catch web security misconfigurations before they reach staging or production environments. The plugin supports mitigation-aware analysis: if security controls like `helmet` (Node.js) or explicit header-setting code are present in the same file, the corresponding finding is automatically suppressed.

The plugin belongs to the **Dynamic Runtime** track and operates with an active risk class, meaning it requires user confirmation before scanning. This classification reflects the nature of the issues it detects -- problems that manifest at runtime in deployed web services.

## Use Cases

### Catching Missing Security Headers Before Code Review

A backend team is building a new REST API in Express.js. During development, engineers focus on business logic and frequently forget to add security headers like `Content-Security-Policy`, `Strict-Transport-Security`, and `X-Frame-Options`. Running `nox-plugin-dast` in the pre-merge CI pipeline flags every endpoint that sends responses without these headers, so reviewers can focus on design rather than checklists.

### Auditing CORS Configuration Across Microservices

An organization with 30+ microservices in Go, Python, and TypeScript needs to ensure none of them allow wildcard CORS origins in production. Rather than manually reviewing each service, the security team runs the DAST plugin across all repositories in a single sweep. Any service using `AllowAllOrigins: true` or `Access-Control-Allow-Origin: *` is flagged immediately.

### Preventing Open Redirect Vulnerabilities in Login Flows

A product team implements a "redirect after login" feature that takes a URL parameter from the request and passes it to `http.Redirect` or `res.redirect`. This is a classic open redirect vulnerability (CWE-601). The DAST plugin catches this pattern at the code level, before a penetration tester finds it in production, giving the team time to implement an allowlist-based redirect approach.

### Enforcing Cookie Security in Django and Flask Applications

A Python team maintains several Django and Flask applications that handle session cookies. The DAST plugin scans for `SESSION_COOKIE_SECURE = False`, `httponly = False`, and other insecure cookie patterns, ensuring that session cookies always have the `Secure`, `HttpOnly`, and `SameSite` flags set before deployment.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/nox-hq/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install nox-hq/nox-plugin-dast
   ```

2. **Create a test project with vulnerable patterns**

   ```bash
   mkdir -p demo-dast && cd demo-dast
   ```

   Create `server.go`:

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("Content-Type", "application/json")
       w.Header().Set("Access-Control-Allow-Origin", "*")

       http.SetCookie(w, &http.Cookie{
           Name:     "session",
           Value:    "abc123",
           Secure:   false,
           HttpOnly: false,
       })

       redirectURL := r.URL.Query().Get("next")
       if redirectURL != "" {
           http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
           return
       }

       fmt.Fprintf(w, `{"status": "ok"}`)
   }

   func main() {
       http.HandleFunc("/api/users", handler)
       http.ListenAndServe(":8080", nil)
   }
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/dast .
   ```

4. **Review findings**

   ```
   DAST-001  HIGH/HIGH    server.go:5   Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options): w.Header().Set("Content-Type", "application/json")
   DAST-002  HIGH/MED     server.go:6   Insecure CORS configuration: w.Header().Set("Access-Control-Allow-Origin", "*")
   DAST-003  MED/HIGH     server.go:24  Missing TLS/HTTPS enforcement: http.ListenAndServe(":8080", nil)
   DAST-004  HIGH/MED     server.go:9   Insecure cookie settings (missing Secure, HttpOnly, or SameSite flags): Secure:   false
   DAST-005  MED/MED      server.go:23  Missing rate limiting on API endpoint: http.HandleFunc("/api/users", handler)
   DAST-006  HIGH/HIGH    server.go:17  Open redirect: user input used in redirect URL: http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)

   6 findings (4 high, 2 medium)
   ```

## Rules

| Rule ID  | Description                                                          | Severity | Confidence | CWE     |
|----------|----------------------------------------------------------------------|----------|------------|---------|
| DAST-001 | Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) | HIGH     | HIGH       | CWE-693 |
| DAST-002 | Insecure CORS configuration (wildcard or credentials with wildcard)  | HIGH     | MEDIUM     | CWE-942 |
| DAST-003 | Missing TLS/HTTPS enforcement (http:// URLs, disabled cert verify)   | MEDIUM   | HIGH       | CWE-319 |
| DAST-004 | Insecure cookie settings (missing Secure, HttpOnly, or SameSite)     | HIGH     | MEDIUM     | CWE-614 |
| DAST-005 | Missing rate limiting on API endpoints                               | MEDIUM   | MEDIUM     | CWE-770 |
| DAST-006 | Open redirect: user input used in redirect URL                       | HIGH     | HIGH       | CWE-601 |

### Mitigations

The plugin automatically suppresses findings when security controls are detected in the same file:

| Rule     | Suppressed When File Contains                                           |
|----------|-------------------------------------------------------------------------|
| DAST-001 | `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, or `helmet` |
| DAST-005 | `rate_limit`, `ratelimit`, `throttle`, `limiter`, `RateLimiter`, or `slowDown` |

## Supported Languages / File Types

| Language   | Extension | Frameworks Detected                                      |
|------------|-----------|----------------------------------------------------------|
| Go         | `.go`     | net/http, Gin, Chi, Echo                                 |
| Python     | `.py`     | Django, Flask, FastAPI                                   |
| JavaScript | `.js`     | Express, Koa, Fastify                                    |
| TypeScript | `.ts`     | Express, NestJS, Fastify                                 |

## Configuration

The plugin uses Nox's standard configuration. No additional configuration is required.

```yaml
# .nox.yaml (optional)
plugins:
  nox/dast:
    enabled: true
```

Directories automatically skipped during scanning: `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`.

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-dast
```

### Standalone

```bash
go install github.com/nox-hq/nox-plugin-dast@latest
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-dast.git
cd nox-plugin-dast
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Build Docker image
docker build -t nox-plugin-dast .

# Clean build artifacts
make clean
```

## Architecture

The plugin operates as a Nox plugin server communicating over stdio using the Nox Plugin SDK. Internally it follows a straightforward pipeline:

1. **File Discovery** -- Recursively walks the workspace directory, filtering by supported file extensions (`.go`, `.py`, `.js`, `.ts`) and skipping common non-source directories.
2. **Line-by-Line Matching** -- Each file is read line-by-line. Every line is tested against all rule patterns for the matching file extension. Rules use compiled regular expressions grouped by file extension to support language-specific syntax patterns.
3. **Mitigation Check** -- Before emitting findings, the full file content is checked for mitigation patterns. If a known security control is present anywhere in the file, the associated rule's findings are suppressed for that file.
4. **Finding Emission** -- Matched lines that are not mitigated produce findings with rule ID, severity, confidence, CWE identifier, file location, and the matched source line.

The plugin registers a single tool (`scan`) under the `dast` capability with active risk classification, requiring user confirmation before execution.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-dast).

When adding new rules:
1. Define the rule in the `rules` slice with an ID, severity, confidence, message, CWE, and per-extension regex patterns.
2. Add corresponding test cases in `main_test.go` with sample files in `testdata/`.
3. Consider whether a mitigation pattern should be added to suppress findings when known controls are present.

## License

Apache-2.0
