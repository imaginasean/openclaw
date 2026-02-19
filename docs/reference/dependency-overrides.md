# Dependency Overrides

The `pnpm.overrides` section in `package.json` pins transitive dependencies to
versions that address known security vulnerabilities. This document records the
rationale for each override. Review quarterly and remove when the parent package
ships the fix natively.

| Package | Pinned Version | CVE / Advisory | Severity | Description |
|---------|---------------|----------------|----------|-------------|
| `fast-xml-parser` | 5.3.4 | CVE-2026-25128 | High (7.5) | RangeError DoS via out-of-range numeric entities (`&#9999999;`). Crashes applications parsing untrusted XML. Fixed in 5.3.4. |
| `form-data` | 2.5.4 | CVE-2025-7783 | Critical (9.4) | Predictable multipart boundary values via `Math.random()`. Enables HTTP parameter injection. Fixed in 2.5.4. |
| `qs` | 6.14.2 | CVE-2025-15284 | High | Resource exhaustion via crafted query strings in qs <6.14.1. Version 6.14.2 includes additional hardening. |
| `@sinclair/typebox` | 0.34.48 | Compatibility | N/A | Pinned for API compatibility with the gateway schema validation layer. Not a security override. |
| `tar` | 7.5.9 | CVE-2026-24842 | High (8.2) | Directory traversal via hardlink path resolution mismatch. Allows reading/writing files outside extraction root. Fixed in 7.5.7; pinned to 7.5.9 for additional fixes. |
| `tough-cookie` | 4.1.3 | CVE-2023-26136 | Critical (9.8) | Prototype pollution via cookie domain/path fields when `rejectPublicSuffixes=false`. Fixed in 4.1.3. |
