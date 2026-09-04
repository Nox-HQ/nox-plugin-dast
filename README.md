# nox-plugin-dast

**Active DAST probing of a running web or API endpoint.**

## Overview

`nox-plugin-dast` sends real HTTP requests to a URL you give it and reports what
the responses reveal: missing security headers, permissive CORS, missing TLS,
insecure cookies, absent rate limiting, and open redirects.

**It does not analyse source code.** Every check needs a live endpoint. There is
no file walking, no language support and no framework detection — earlier
revisions of this README described all three, and none of it was ever true of
the code.

Two consequences worth stating plainly:

- **`nox scan` cannot drive this plugin.** A scan invokes the `scan` tool with
  `workspace_root` and `exclude` and no target, because nox scans source trees.
  Listing `nox/dast` in `plugins.required` therefore contributes nothing to a
  scan; since v0.3.4 it emits a warning saying so instead of returning silently.
- **Use `nox plugin call`.** That is the supported way to run it, and the target
  is explicit at the point of use.

The plugin belongs to the **Dynamic Runtime** track with an active risk class
and requires confirmation, because it sends traffic to a host you name — five
rapid requests for the rate-limit check, and redirect probes against common
parameters. Only point it at systems you are authorised to test.

## Use Cases

### Checking a deployment's response headers

A service is behind a reverse proxy that is supposed to add CSP, HSTS and
`X-Frame-Options`. Whether it actually does is a property of the deployment, not
of the source — a header added in nginx is invisible to any code scanner. One
call against the deployed URL answers it.

### Confirming a CORS policy in the environment that serves it

CORS is frequently set by a gateway or CDN rather than the application. Sending
an `OPTIONS` request with a foreign `Origin` shows what the deployed stack
actually returns, wildcard or not.

### Verifying rate limiting exists where it is supposed to

A burst of five requests shows whether the endpoint returns `429` or any
recognised rate-limit header. Absence is reported at medium confidence: a
threshold above five will not be observed, and this check cannot tell an
unprotected endpoint from a generous one.

### Post-deploy verification in a pipeline

Run it against staging after a deploy, with the environment's URL as
`target_url`, to catch a header or TLS regression that source review cannot see.

## 5-Minute Demo

### Prerequisites

- [Nox](https://github.com/nox-hq/nox) installed
- A URL you are authorised to probe

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install nox-hq/nox-plugin-dast
   ```

2. **Permit it in a working directory**

   The plugin is active risk class and needs confirmation, so a passive policy
   refuses it. Create `.nox.yaml`:

   ```yaml
   plugin_policy:
     allowed_network_hosts:
       - "your-host.example.com"
     max_risk_class: active
     allow_confirmation_required: true
   ```

3. **Probe the endpoint**

   ```bash
   nox plugin call nox/dast scan target_url=https://your-host.example.com
   ```

   ```json
   {
     "findings": [
       {
         "rule_id": "DAST-001",
         "message": "Missing security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options",
         "metadata": {
           "cwe": "CWE-693",
           "missing_headers": "Content-Security-Policy,Strict-Transport-Security,X-Frame-Options,X-Content-Type-Options",
           "target_url": "https://your-host.example.com"
         }
       },
       {
         "rule_id": "DAST-005",
         "message": "No rate limiting detected after 5 rapid requests",
         "metadata": { "cwe": "CWE-770", "burst_count": "5" }
       }
     ]
   }
   ```

   Verify a header finding yourself with `curl -sSI https://your-host.example.com`
   — the checks are simple enough that you should be able to.

## Rules

Severity and confidence vary per finding within a rule, so the ranges below are
what the code emits rather than one fixed grade.

| Rule ID  | What it probes                                                            | Severity        | Confidence      | CWE     |
|----------|---------------------------------------------------------------------------|-----------------|-----------------|---------|
| DAST-001 | Response headers absent: CSP, HSTS, X-Frame-Options, X-Content-Type-Options | HIGH            | HIGH            | CWE-693 |
| DAST-002 | CORS response to an `OPTIONS` with a foreign `Origin`                      | HIGH            | MEDIUM / HIGH   | CWE-942 |
| DAST-003 | The target URL's scheme is `http://`                                       | MEDIUM / HIGH   | HIGH            | CWE-319 |
| DAST-004 | `Set-Cookie` missing `Secure`, `HttpOnly` or `SameSite`                    | HIGH            | MEDIUM          | CWE-614 |
| DAST-005 | No `429` or rate-limit header after five rapid requests                    | MEDIUM          | MEDIUM          | CWE-770 |
| DAST-006 | A common redirect parameter is honoured to an external host                | HIGH            | HIGH            | CWE-601 |
| DAST-007 | Instruction override accepted *(opt-in)*                                   | HIGH            | HIGH            | —       |
| DAST-008 | System prompt leaked *(opt-in)*                                            | HIGH            | MEDIUM          | —       |
| DAST-009 | Tool smuggling accepted *(opt-in)*                                         | CRITICAL        | HIGH            | —       |
| DAST-010 | Cost amplification unbounded *(opt-in)*                                    | HIGH            | HIGH            | —       |

DAST-005 deserves a caveat: five requests cannot distinguish an endpoint with no
rate limiting from one whose threshold is above five. It is reported at medium
confidence for that reason, and on a static site behind a CDN it is usually
noise.

### AI probes (opt-in)

`DAST-007`–`DAST-010` send instruction-override, system-prompt-leak,
tool-smuggling and cost-amplification payloads. They are **off by default** so a
generic scan against a non-AI host never sends them. Opt in per call:

```bash
nox plugin call nox/dast scan target_url=https://your-ai-host ai_probes=true
```

## Configuration

The target is an argument, not configuration:

```bash
nox plugin call nox/dast scan target_url=https://your-host
```

A URL without a scheme is assumed to be `https://`.

Because the plugin is active risk class and needs confirmation, a passive policy
refuses it. To permit it, widen the sandbox in `.nox.yaml`:

```yaml
plugin_policy:
  allowed_network_hosts:
    - "your-host.example.com"
  max_risk_class: active
  allow_confirmation_required: true
```

Overrides are one-directional: you can widen an allowlist but not empty one.

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

The plugin is a Nox plugin server speaking the Plugin SDK protocol over stdio.
It registers one tool, `scan`, under the `dast` capability, with active risk
classification and confirmation required.

`scan` takes `target_url` and runs six checks against it, each an HTTP exchange:

1. **DAST-001** — `GET`, then inspect the response headers.
2. **DAST-002** — `OPTIONS` with a foreign `Origin`, then inspect the CORS
   response headers.
3. **DAST-003** — parse the URL scheme; `http://` is reported, `https://` is not.
4. **DAST-004** — `GET`, then inspect `Set-Cookie` attributes.
5. **DAST-005** — five rapid `GET`s, looking for `429` or a rate-limit header.
6. **DAST-006** — request common redirect parameters and follow what comes back.

`DAST-007`–`DAST-010` run only when `ai_probes` is set.

There is no file discovery, no regex matching against source, and no
mitigation-by-file-content step. Nothing on disk is read.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-dast).

When adding new rules:
1. Define the rule in the `rules` slice with an ID, severity, confidence, message, CWE, and per-extension regex patterns.
2. Add corresponding test cases in `main_test.go` with sample files in `testdata/`.
3. Consider whether a mitigation pattern should be added to suppress findings when known controls are present.

## License

Apache-2.0
