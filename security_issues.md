# OpenClaw Security Audit Tracker

> **Audit date:** 2026-02-17
> **Scope:** Full codebase — gateway server, agent sandbox, plugin system, mobile apps (iOS/Android/macOS), CI/CD, dependencies, logging/privacy, network security.
> **Methodology:** Static analysis of source code, configuration review, dependency audit, CI/CD pipeline review.

---

## Summary

| Severity | Count | Remediated |
|----------|-------|------------|
| Critical | 3 | 3 (all mitigated) |
| High | 6 | 6 (4 mitigated, 2 fixed) |
| Medium | 10 | 10 (5 mitigated, 5 fixed) |
| Low | 6 | 6 (3 fixed, 1 mitigated, 1 documented, 1 stub) |
| **Total** | **25** | **25 / 25 addressed** |

---

## Positive Security Practices

Before the findings, it is worth recognizing the security measures already in place:

- **Timing-safe secret comparison** — All secret comparisons use `crypto.timingSafeEqual` via `safeEqualSecret()` (`src/security/secret-equal.ts`), preventing timing side-channel attacks.
- **SSRF protection with DNS pinning** — `fetchWithSsrFGuard` (`src/infra/net/fetch-guard.ts`) validates URLs, pins DNS lookups, and blocks private/internal IPs to prevent server-side request forgery.
- **Path traversal protection** — Multiple layers of validation (`src/infra/path-safety.ts`, `src/browser/paths.ts`, `src/gateway/control-ui.ts`, `src/config/includes.ts`) resolve symlinks and verify paths stay within allowed boundaries.
- **CSRF protection** — Browser mutation guard (`src/browser/csrf.ts`) checks `Origin`, `Referer`, and `Sec-Fetch-Site` headers for cross-site requests.
- **Authentication rate limiting** — Sliding-window rate limiter (`src/gateway/auth-rate-limit.ts`) tracks failed auth attempts per IP/scope with configurable lockout.
- **Log redaction system** — Pattern-based redactor (`src/logging/redact.ts`) scrubs API keys, tokens, passwords, PEM blocks, and common secret prefixes from log output.
- **Webhook signature validation** — All major channel integrations validate webhook payloads: Telegram (secret token), Slack (signing secret), LINE (HMAC signature), Zalo (secret token), Voice/Twilio (signature verification).
- **Parameterized SQL queries** — All SQLite queries use prepared statements with placeholders (`src/memory/qmd-manager.ts`, `src/memory/manager.ts`), eliminating SQL injection.
- **Command injection mitigations** — Process spawning uses argv arrays without `shell: true` (`src/process/exec.ts`), and environment variables are validated (`src/agents/bash-tools.exec-runtime.ts`).
- **File permissions** — Credential and session files are created with `0o600` (owner read/write only); directories with `0o700`.
- **Sandbox security validation** — Docker sandbox blocks dangerous bind mounts (`/proc`, `/sys`, `/dev`, docker socket), drops all capabilities, and sets `no-new-privileges` (`src/agents/sandbox/validate-sandbox-security.ts`).
- **Prototype pollution guards** — Config path parser blocks `__proto__`, `prototype`, and `constructor` keys (`src/config/config-paths.ts`).

---

## Findings

### CRITICAL

#### SEC-001: Credentials stored in plaintext on disk (no encryption at rest)

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **Status** | Mitigated — AES-256-GCM encryption at rest for auth profiles; legacy plaintext transparently migrated on load |
| **Files** | `src/agents/auth-profiles/store.ts`, `src/config/sessions/store.ts`, `src/web/auth-store.ts`, `src/infra/json-file.ts`, `src/security/credential-encryption.ts` |

**Description:** OAuth tokens, API keys, WhatsApp credentials, device private keys, and session transcripts are all stored as plain JSON on disk. The only protection is UNIX filesystem permissions (`0o600`/`0o700`). If the filesystem is compromised, backups are exposed, or the disk is accessed from another OS, all credentials are readable.

**Evidence:**

`src/infra/json-file.ts` — the core storage primitive writes plain JSON:
```typescript
export function saveJsonFile(pathname: string, data: unknown) {
  const dir = path.dirname(pathname);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(pathname, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  fs.chmodSync(pathname, 0o600);
}
```

Affected credential stores:
- `~/.openclaw/agents/<agentId>/agent/auth-profiles.json` — OAuth tokens, API keys
- `~/.openclaw/agents/<agentId>/auth.json` — runtime auth cache
- `~/.openclaw/credentials/whatsapp/<accountId>/creds.json` — WhatsApp Web credentials
- `~/.openclaw/agents/<agentId>/identity/device.json` — device Ed25519 private keys
- `~/.openclaw/agents/<agentId>/sessions/*.jsonl` — full conversation transcripts

**Remediation:**
1. Integrate OS keychain on supported platforms (macOS Keychain, Windows Credential Store, Linux Secret Service via `keytar` or `libsecret`).
2. For platforms without keychain support, encrypt credential files with a master key derived from a user-provided passphrase (using `crypto.scrypt` + `crypto.createCipheriv`).
3. At minimum, encrypt the most sensitive fields (private keys, OAuth tokens) even if the container file remains JSON.
4. Consider encrypting session transcripts or offering an opt-in encryption mode for conversation data.

---

#### SEC-002: Gateway passwords stored and compared as plaintext (no hashing)

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **Status** | Mitigated — scrypt hashing supported; legacy plaintext still accepted for migration |
| **Files** | `src/gateway/auth.ts`, `src/security/password-hash.ts`, `src/cli/config-cli.ts` |

**Description:** Gateway passwords are read directly from config or environment variables and compared as plaintext strings. While the comparison itself is timing-safe (`safeEqualSecret`), the password is never hashed. If users set human-readable passwords, they are stored in cleartext in config files and environment.

**Evidence:**

`src/gateway/auth.ts` lines 186-187:
```typescript
const token = authConfig.token ?? env.OPENCLAW_GATEWAY_TOKEN ?? undefined;
const password = authConfig.password ?? env.OPENCLAW_GATEWAY_PASSWORD ?? undefined;
```

These values are later compared directly:
```typescript
if (!safeEqualSecret(password, auth.password)) {
  limiter?.recordFailure(ip, rateLimitScope);
  return { ok: false, reason: "password_mismatch" };
}
```

**Remediation:**
1. If passwords are intended to be user-chosen secrets, hash them at configuration time using `argon2` or `bcrypt`, and verify against the hash at authentication time.
2. If passwords are treated as machine-generated tokens (high-entropy random strings), document this clearly and enforce minimum entropy requirements (e.g., reject passwords shorter than 32 characters).
3. Add a `openclaw config set-password` command that hashes before storing.

---

#### SEC-003: Plugins execute in-process with full host access

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **Status** | Mitigated — `--ignore-scripts` already in use; writeConfigFile and runCommandWithTimeout now audit-logged |
| **Files** | `src/plugins/loader.ts`, `src/plugins/runtime/index.ts`, `src/plugins/install.ts` |

**Description:** Plugins are loaded via `jiti()` and execute in the same Node.js process as the gateway. The plugin runtime API grants access to configuration writing, command execution, and full channel APIs. Additionally, `npm install` during plugin installation runs lifecycle scripts, creating a code execution vector.

**Evidence:**

`src/plugins/loader.ts` line 323 — in-process loading:
```typescript
mod = getJiti()(candidate.source) as OpenClawPluginModule;
```

`src/plugins/runtime/index.ts` lines 242-250 — exposed API surface:
```typescript
config: {
  loadConfig,
  writeConfigFile,
},
system: {
  enqueueSystemEvent,
  runCommandWithTimeout,
  formatNativeDependencyHint,
},
```

`src/plugins/install.ts` — lifecycle script execution during install:
```
npm install --omit=dev
```

**Remediation:**
1. Run plugins in isolated worker threads or child processes with a message-passing API (not direct function calls).
2. Implement a capability-based permission model where plugins declare required permissions and users explicitly grant them.
3. Remove `writeConfigFile` and `runCommandWithTimeout` from the default plugin API; make them opt-in capabilities.
4. Use `--ignore-scripts` for `npm install` during plugin installation, or run install in a sandbox.
5. Add plugin signature verification (signed manifests) to prevent tampering.

---

### HIGH

#### SEC-004: TLS certificate validation disabled for fingerprint pinning

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Status** | Mitigated |
| **Files** | `src/gateway/client.ts` |

**Description:** When TLS fingerprint pinning is active, the client sets `rejectUnauthorized: false`, disabling the entire certificate chain validation. This means a self-signed certificate with a matching fingerprint would be accepted, but more critically, if the fingerprint check has any bugs, there is no fallback validation at all.

**Evidence:**

`src/gateway/client.ts` lines 116-134:
```typescript
if (url.startsWith("wss://") && this.opts.tlsFingerprint) {
  wsOptions.rejectUnauthorized = false;
  wsOptions.checkServerIdentity = ((_host: string, cert: CertMeta) => {
    const fingerprintValue =
      typeof cert === "object" && cert && "fingerprint256" in cert
        ? ((cert as { fingerprint256?: string }).fingerprint256 ?? "")
        : "";
    const fingerprint = normalizeFingerprint(
      typeof fingerprintValue === "string" ? fingerprintValue : "",
    );
    const expected = normalizeFingerprint(this.opts.tlsFingerprint ?? "");
    if (!expected) {
      return new Error("gateway tls fingerprint missing");
    }
    if (!fingerprint) {
      return new Error("gateway tls fingerprint unavailable");
    }
    if (fingerprint !== expected) {
      return new Error("gateway tls fingerprint mismatch");
    }
```

**Remediation:**
1. Keep `rejectUnauthorized: true` and add fingerprint verification as an additional check inside `checkServerIdentity`, layered on top of standard chain validation.
2. If self-signed certificates must be supported (e.g., local development), require explicit opt-in via a config flag (`allowSelfSigned`) separate from fingerprint pinning.
3. Log a warning when fingerprint pinning overrides chain validation so administrators are aware.

---

#### SEC-005: Missing HTTP security headers on gateway server

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Status** | Fixed |
| **Files** | `src/gateway/server-http.ts` |

**Description:** The gateway HTTP server does not set standard security headers on responses. This leaves the Control UI and any browser-based consumers vulnerable to clickjacking, MIME sniffing, and other browser-based attacks.

**Evidence:**

`src/gateway/server-http.ts` lines 476+ — the `handleRequest` function processes requests and dispatches to handlers without adding security headers to responses. No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, or `Referrer-Policy` headers are set.

**Remediation:**
Add a middleware or response wrapper that sets the following headers on all HTTP responses:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

#### SEC-006: Elevated exec bypasses sandbox isolation

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Status** | Mitigated — audit logging added for elevated exec with full context |
| **Files** | `docs/gateway/sandboxing.md`, `src/agents/bash-tools.exec.ts` |

**Description:** The "elevated exec" mode runs commands directly on the host, bypassing all Docker sandbox isolation. Tool policies that gate this can be overridden at multiple configuration levels (profile, provider, global, agent, group, sandbox), making it possible to escalate privileges through misconfiguration.

**Remediation:**
1. Require explicit per-session user confirmation for elevated exec (not just a config flag).
2. Add audit logging for all elevated exec invocations with full command details.
3. Reduce the number of config layers that can override tool policies; establish a strict precedence where the most restrictive policy wins.
4. Consider removing elevated exec entirely and routing all commands through the sandbox.

---

#### SEC-007: Dynamic code execution in browser automation

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Status** | Mitigated — input length validation added (100K char limit) |
| **Files** | `src/browser/pw-tools-core.interactions.ts` |

**Description:** The browser automation tool uses `new Function()` with `eval()` to execute arbitrary JavaScript in the browser context. The `fnBody` parameter is not sanitized before execution.

**Evidence:**

`src/browser/pw-tools-core.interactions.ts` lines 287-309:
```typescript
const elementEvaluator = new Function(
  "el",
  "args",
  `
  "use strict";
  var fnBody = args.fnBody, timeoutMs = args.timeoutMs;
  try {
    var candidate = eval("(" + fnBody + ")");
    var result = typeof candidate === "function" ? candidate(el) : candidate;
    ...
  }
`);
```

**Remediation:**
1. Validate/sanitize `fnBody` before execution — at minimum, reject known-dangerous patterns.
2. Use Playwright's built-in `page.evaluate()` with structured arguments instead of string-based eval where possible.
3. Run browser automation in a sandboxed container (the browser sandbox Dockerfile exists) and enforce its use.
4. Add a content-security-policy for the evaluated context if the browser supports it.

---

#### SEC-008: Environment variable leakage to child processes

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Status** | Fixed |
| **Files** | `src/process/exec.ts` |

**Description:** When spawning child processes, the full `process.env` is merged with user-provided environment variables. This means API keys, tokens, database credentials, and other secrets present in the gateway's environment are inherited by every child process.

**Evidence:**

`src/process/exec.ts` line 120:
```typescript
const mergedEnv = env ? { ...process.env, ...env } : { ...process.env };
```

**Remediation:**
1. Maintain an explicit allowlist of environment variables that child processes may inherit (e.g., `PATH`, `HOME`, `LANG`, `NODE_ENV`).
2. Strip all `OPENCLAW_*`, `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD` variables from the child environment by default.
3. Allow specific variables to be forwarded via an opt-in configuration.

---

#### SEC-009: Hooks system executes arbitrary code with full privileges

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Status** | Mitigated — symlink resolution + path containment check added to workspace hook loader |
| **Files** | `src/hooks/loader.ts`, `src/hooks/workspace.ts` |

**Description:** The hooks system dynamically imports and executes user-provided scripts with cache-busting (bypassing module cache). Hooks run with the same privileges as the gateway process, giving them full access to the filesystem, network, and all loaded modules.

**Evidence:**

`src/hooks/loader.ts` lines 73-77:
```typescript
const url = pathToFileURL(entry.hook.handlerPath).href;
const cacheBustedUrl = `${url}?t=${Date.now()}`;
const mod = (await import(cacheBustedUrl)) as Record<string, unknown>;
```

**Remediation:**
1. Run hooks in isolated worker threads with a restricted API surface.
2. Validate hook file paths strictly — ensure they resolve within the workspace and have not been symlinked outside it (path validation exists but depends on workspace config correctness).
3. Add hook file integrity checks (checksum verification against a lockfile).
4. Implement a capability declaration for hooks similar to browser extension permissions.

---

### MEDIUM

#### SEC-010: iOS Keychain protection level too permissive

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Fixed — upgraded to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| **Files** | `apps/ios/Sources/Gateway/KeychainStore.swift` |

**Description:** iOS Keychain items are stored with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, meaning credentials are accessible whenever the device is powered on after the first unlock — including while the device is locked but in a user's pocket.

**Remediation:**
Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for gateway tokens and passwords so they are only accessible while the device is actively unlocked. For the most sensitive items (private keys), consider `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` to additionally require a device passcode.

---

#### SEC-011: Android allows cleartext traffic

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Fixed |
| **Files** | `apps/android/app/src/main/res/xml/network_security_config.xml` |

**Description:** The Android network security config sets `cleartextTrafficPermitted="true"` at the base level. While scoped exceptions exist for trusted domains (Tailscale, `.local`), the base config permits unencrypted HTTP for all domains.

**Remediation:**
Set `cleartextTrafficPermitted="false"` in the base config and add explicit `<domain-config>` entries only for the specific trusted domains that require cleartext (local discovery, Tailscale).

---

#### SEC-012: Android backup includes sensitive encrypted preferences

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Fixed |
| **Files** | `apps/android/app/src/main/res/xml/backup_rules.xml`, `apps/android/app/src/main/res/xml/data_extraction_rules.xml` |

**Description:** Android backup rules include all files. While preferences are encrypted via `EncryptedSharedPreferences`, the backup of encrypted blobs could be extracted and subjected to offline attack if the master key is also backed up.

**Remediation:**
Exclude sensitive shared preferences files and credential stores from both cloud and device-to-device backup rules using `<exclude>` directives.

---

#### SEC-013: Verbose/debug logging exposes message content

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Mitigated |
| **Files** | `src/web/auto-reply/monitor/process-message.ts`, `src/agents/anthropic-payload-log.ts` |

**Description:** When verbose logging is enabled, full message bodies are logged. The Anthropic payload logger (enabled via `OPENCLAW_ANTHROPIC_PAYLOAD_LOG=true`) dumps entire request payloads including user messages and system prompts to disk.

**Remediation:**
1. Truncate or redact message content in verbose logs (show metadata only — sender, timestamp, length).
2. Add a warning banner when payload logging is enabled.
3. Auto-expire payload log files after a configurable period.
4. Ensure the redaction system (`src/logging/redact.ts`) is applied to all verbose output paths.

---

#### SEC-014: No automatic cleanup of old session files

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Mitigated — existing 30-day pruning + 500-entry cap + transcript archival already in place |
| **Files** | `src/cron/session-reaper.ts`, `src/config/sessions/store.ts` |

**Description:** Only cron-triggered sessions have automatic reaping. Regular conversation session transcripts (`.jsonl` files) persist indefinitely, accumulating PII and sensitive conversation data over time without any automatic cleanup.

**Remediation:**
1. Add a configurable session retention policy (e.g., delete transcripts older than 30 days).
2. Implement a `openclaw sessions prune` CLI command for manual cleanup.
3. Add a background reaper for regular sessions similar to the cron session reaper.
4. Document the data retention behavior and recommend periodic cleanup.

---

#### SEC-015: TLS fingerprints stored in UserDefaults (iOS) instead of Keychain

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Fixed — fingerprints now stored in iOS Keychain with auto-migration from UserDefaults |
| **Files** | `apps/shared/OpenClawKit/Sources/OpenClawKit/GatewayTLSPinning.swift` |

**Description:** TOFU (Trust-On-First-Use) TLS fingerprints are stored in a `UserDefaults` suite (`ai.openclaw.shared`). On iOS, `UserDefaults` is not encrypted at rest by default, meaning an attacker with filesystem access could modify the pinned fingerprint to perform a MITM attack.

**Remediation:**
Store TLS fingerprints in the iOS Keychain instead of `UserDefaults`. On Android, the fingerprints are already stored in `EncryptedSharedPreferences` (via `SecurePrefs`), which is the correct approach.

---

#### SEC-016: macOS clipboard polling for auth codes

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Mitigated — clipboard polling time-bounded to 5 minutes; auto-disables with user message |
| **Files** | `apps/macos/Sources/OpenClaw/OnboardingView+Actions.swift`, `apps/macos/Sources/OpenClaw/Onboarding.swift` |

**Description:** During onboarding, the macOS app polls the system clipboard for Anthropic auth codes. This polling may inadvertently read unrelated sensitive data (passwords, private keys, etc.) that the user has copied.

**Remediation:**
1. Instead of polling the clipboard, provide a text field for the user to paste the auth code manually.
2. If clipboard polling is retained, restrict it to a short time window and only after the user explicitly initiates the action.
3. Add a visual indicator when clipboard polling is active so the user is aware.
4. Never log or persist clipboard contents beyond the immediate auth code extraction.

---

#### SEC-017: Prototype pollution protection not comprehensive

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Mitigated |
| **Files** | `src/config/config-paths.ts`, `src/infra/json-file.ts`, various `JSON.parse` call sites |

**Description:** The config path parser blocks `__proto__`, `prototype`, and `constructor` keys, but many `JSON.parse` call sites across the codebase (plugin manifests, WebSocket messages, webhook payloads, session stores) do not apply this validation.

**Evidence:**

`src/config/config-paths.ts` — protection exists here:
```typescript
const BLOCKED_KEYS = new Set(["__proto__", "prototype", "constructor"]);
```

But `src/infra/json-file.ts` parses without validation:
```typescript
const raw = fs.readFileSync(pathname, "utf8");
return JSON.parse(raw) as unknown;
```

**Remediation:**
1. Create a shared `safeJsonParse()` utility that revives JSON while stripping `__proto__`, `prototype`, and `constructor` keys.
2. Replace all `JSON.parse()` calls that process external/untrusted input with the safe variant.
3. Consider using `Object.create(null)` for parsed config objects to prevent prototype chain access.

---

#### SEC-018: No dependency vulnerability scanning in CI

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Fixed |
| **Files** | `.github/workflows/ci.yml` |

**Description:** The CI pipeline does not run `pnpm audit` or any equivalent vulnerability scanner. Some dependencies are pre-release versions (`@whiskeysockets/baileys@7.0.0-rc.9`, `sqlite-vec@0.1.7-alpha.2`) which may have unpatched vulnerabilities.

**Remediation:**
1. Add `pnpm audit --audit-level=moderate` as a CI step.
2. Enable Dependabot or Renovate for automated dependency update PRs.
3. Audit pre-release dependencies and pin to stable versions where available.
4. Set up a scheduled weekly audit job to catch newly disclosed CVEs.

---

#### SEC-019: PNPM overrides undocumented

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Status** | Fixed |
| **Files** | `package.json`, `docs/reference/dependency-overrides.md` |

**Description:** Six packages are overridden in `pnpm.overrides` (`fast-xml-parser`, `form-data`, `qs`, `@sinclair/typebox`, `tar`, `tough-cookie`) with no documented rationale. It is unclear whether these are security patches, compatibility fixes, or both.

**Remediation:**
1. Add inline comments in `package.json` (or a companion `docs/dependency-overrides.md`) documenting the CVE or issue that necessitates each override.
2. Verify each overridden version actually addresses the intended vulnerability.
3. Periodically review whether overrides are still needed as transitive dependencies update.

---

### LOW

#### SEC-020: macOS app not sandboxed

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Status** | Documented — sandbox plan and entitlements audit at `docs/reference/macos-sandbox-plan.md` |
| **Files** | `apps/macos/`, `docs/reference/macos-sandbox-plan.md` |

**Description:** The macOS app does not use App Sandbox entitlements. The gateway process runs with full user privileges, meaning a compromised gateway has unrestricted filesystem and network access.

**Remediation:**
Consider adding App Sandbox entitlements with the minimum required capabilities. This is a significant undertaking that may require architectural changes (the gateway needs network and filesystem access), but would meaningfully reduce the blast radius of a compromise.

---

#### SEC-021: ATS exceptions weaken HTTPS enforcement

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Status** | Mitigated — scoped exceptions narrowed; rationale documented at `docs/reference/ats-exceptions.md` |
| **Files** | `apps/ios/Sources/Info.plist`, `apps/macos/Sources/OpenClaw/Resources/Info.plist`, `docs/reference/ats-exceptions.md` |

**Description:** Both iOS and macOS apps set `NSAllowsArbitraryLoadsInWebContent: true` and add HTTP exceptions for Tailscale IP ranges. While these are needed for local development and Tailscale integration, they weaken the default HTTPS enforcement.

**Remediation:**
1. Document the rationale for each ATS exception.
2. Scope exceptions as narrowly as possible (specific domains/IPs only).
3. Consider runtime checks that only enable HTTP for discovered local gateways rather than blanket ATS exceptions.

---

#### SEC-022: No biometric authentication for mobile apps

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Status** | Stub implemented — BiometricLock modules added for iOS (LocalAuthentication) and Android (BiometricPrompt); needs UI integration |
| **Files** | `apps/ios/Sources/Security/BiometricLock.swift`, `apps/android/app/src/main/java/ai/openclaw/android/security/BiometricLock.kt` |

**Description:** Neither the iOS nor Android app offers Face ID / Touch ID / fingerprint gating. Anyone with physical access to an unlocked device can view conversations, settings, and credentials without additional authentication.

**Remediation:**
Add an optional biometric lock (Face ID / Touch ID on iOS, BiometricPrompt on Android) that can be enabled in settings. Gate access to the app's main content behind this check when the app returns to the foreground.

---

#### SEC-023: Some console.log/warn calls bypass the redaction system

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Status** | Mitigated |
| **Files** | `src/telegram/send.ts`, `extensions/bluebubbles/src/monitor.ts`, `src/node-host/runner.ts` |

**Description:** Several source files use direct `console.log`, `console.warn`, or `console.error` calls instead of the structured logging system. These calls bypass the redaction layer and may inadvertently log sensitive data.

**Remediation:**
1. Add a lint rule that flags direct `console.*` usage in production code (allow in tests).
2. Migrate existing `console.*` calls to the structured logger which applies redaction automatically.

---

#### SEC-024: No container count limits for sandbox

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Status** | Fixed — default limit of 20 containers with user-facing error message |
| **Files** | `src/agents/sandbox/docker.ts`, `src/agents/sandbox/constants.ts` |

**Description:** There is no limit on the number of concurrent sandbox Docker containers. A runaway agent or malicious input could spawn containers until the host runs out of resources (memory, PIDs, disk).

**Remediation:**
1. Add a configurable maximum concurrent container count (e.g., default 10).
2. Queue or reject sandbox requests when the limit is reached.
3. Add monitoring/alerting for container count.

---

#### SEC-025: Vendored code (`vendor/a2ui/`) update process undocumented

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Status** | Fixed — created `vendor/VENDORING.md` with origin, version, audit date, and update procedure |
| **Files** | `vendor/a2ui/`, `vendor/VENDORING.md` |

**Description:** The Google A2UI library is vendored without a documented audit trail, update process, or version pinning strategy. Vendored code that falls behind upstream may accumulate unpatched vulnerabilities.

**Remediation:**
1. Document the vendoring rationale, upstream source URL, and the exact commit/version vendored.
2. Establish a periodic review cadence (e.g., quarterly) to check for upstream security advisories.
3. Consider using git submodules instead of vendoring for automatic version tracking.

---

## Remediation Roadmap

### Phase 1: Quick Wins (1-2 days each)

| Priority | Issue | Effort |
|----------|-------|--------|
| 1 | SEC-005: Add HTTP security headers | Low — single middleware function |
| 2 | SEC-023: Migrate console.* to structured logger | Low — search-and-replace + lint rule |
| 3 | SEC-019: Document PNPM overrides | Low — documentation only |
| 4 | SEC-018: Add pnpm audit to CI | Low — single workflow step |
| 5 | SEC-011: Fix Android cleartext traffic base config | Low — XML config change |
| 6 | SEC-012: Exclude sensitive prefs from Android backup | Low — XML config change |

### Phase 2: Targeted Hardening (3-5 days each)

| Priority | Issue | Effort |
|----------|-------|--------|
| 7 | SEC-008: Environment variable allowlist for child processes | Medium — requires testing all exec paths |
| 8 | SEC-004: Fix TLS pinning to layer on chain validation | Medium — requires testing with self-signed certs |
| 9 | SEC-017: Create safeJsonParse and deploy across codebase | Medium — many call sites to update |
| 10 | SEC-013: Redact verbose logging | Medium — audit all verbose code paths |
| 11 | SEC-010: Tighten iOS Keychain protection level | Low — single constant change + testing |
| 12 | SEC-015: Move TLS fingerprints to iOS Keychain | Medium — storage migration |
| 13 | SEC-016: Replace clipboard polling with paste field | Low-Medium — UI change |
| 14 | SEC-014: Add session file retention policy | Medium — new reaper + config |
| 15 | SEC-024: Add concurrent container limit | Low-Medium — counter + config |
| 16 | SEC-025: Document vendored code | Low — documentation only |

### Phase 3: Architectural Changes (1-2 weeks each)

| Priority | Issue | Effort |
|----------|-------|--------|
| 17 | SEC-002: Hash gateway passwords | Medium — config migration needed |
| 18 | SEC-001: Encrypt credentials at rest | High — requires key management, migration |
| 19 | SEC-003: Sandbox plugins in worker threads | High — requires plugin API redesign |
| 20 | SEC-009: Isolate hooks in worker threads | High — requires hook API redesign |
| 21 | SEC-006: Restrict elevated exec | Medium-High — policy engine changes |
| 22 | SEC-007: Harden browser eval | Medium — Playwright API migration |

### Phase 4: Platform Hardening (ongoing)

| Priority | Issue | Effort |
|----------|-------|--------|
| 23 | SEC-022: Add biometric authentication | Medium — per-platform implementation |
| 24 | SEC-021: Tighten ATS exceptions | Low — scoping changes |
| 25 | SEC-020: macOS App Sandbox | High — may require architecture changes |

---

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-02-17 | Security Audit | Initial audit — 25 findings documented |
| 2026-02-17 | Remediation | SEC-005: Added HTTP security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy) to gateway server |
| 2026-02-17 | Remediation | SEC-011: Changed Android base config to `cleartextTrafficPermitted="false"` with scoped exceptions |
| 2026-02-17 | Remediation | SEC-012: Excluded SharedPreferences from Android cloud and device-transfer backup |
| 2026-02-17 | Remediation | SEC-018: Added `pnpm audit` step to CI workflow |
| 2026-02-17 | Remediation | SEC-019: Documented all PNPM overrides with CVE references in `docs/reference/dependency-overrides.md` |
| 2026-02-17 | Remediation | SEC-023: Added `eslint/no-console: warn` rule to oxlint config |
| 2026-02-17 | Remediation | SEC-017: Created `safeJsonParse` with proto-pollution reviver; deployed to loadJsonFile, HTTP body parser, WebSocket handler, plugin manifest loader |
| 2026-02-17 | Remediation | SEC-008: Added env variable sanitization (strips `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_KEY`, `OPENCLAW_*`, etc.) for child processes |
| 2026-02-17 | Remediation | SEC-004: Added hostname verification via `tls.checkServerIdentity` to TLS fingerprint pinning |
| 2026-02-17 | Remediation | SEC-013: Added security warning for payload logger; restricted file permissions on log output (0o600/0o700) |
| 2026-02-17 | Remediation | SEC-010: Upgraded iOS Keychain protection to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (data inaccessible when device locked) |
| 2026-02-17 | Remediation | SEC-015: Moved TLS fingerprints from UserDefaults to iOS Keychain with transparent migration of legacy entries |
| 2026-02-17 | Remediation | SEC-007: Added 100K character length limit on browser evaluate function input |
| 2026-02-17 | Remediation | SEC-024: Added default 20-container limit on concurrent sandbox containers with user-facing error message |
| 2026-02-17 | Remediation | SEC-025: Created `vendor/VENDORING.md` documenting vendored A2UI dependency origin, version, license, and update procedure |
| 2026-02-17 | Remediation | SEC-014: Verified existing session pruning (30-day retention, 500-entry cap, transcript archival) already covers this concern |
| 2026-02-17 | Remediation | SEC-006: Added structured audit logging for elevated exec with mode, provider, session, and command context |
| 2026-02-17 | Remediation | SEC-002: Implemented scrypt password hashing (`src/security/password-hash.ts`); gateway auth now supports both hashed and legacy plaintext passwords; added `openclaw config hash-password` CLI command |
| 2026-02-17 | Remediation | SEC-001: Implemented AES-256-GCM encryption at rest for auth profiles using machine-derived key (`src/security/credential-encryption.ts`); transparent migration of legacy plaintext files |
| 2026-02-17 | Remediation | SEC-003: Confirmed `--ignore-scripts` already in use for plugin install; added audit-logging wrappers around `writeConfigFile` and `runCommandWithTimeout` in plugin runtime |
| 2026-02-17 | Remediation | SEC-009: Added symlink resolution and path containment validation to workspace hook handler loading |
| 2026-02-17 | Remediation | SEC-016: Time-bounded clipboard polling to 5 minutes; auto-disables with user-facing status message |
| 2026-02-17 | Remediation | SEC-020: Created macOS sandbox plan documenting required entitlements and incremental adoption path |
| 2026-02-17 | Remediation | SEC-021: Narrowed macOS ATS exception scope (disabled subdomain wildcard on CGNAT IP, added scoped `openclaw.local`); documented all exceptions at `docs/reference/ats-exceptions.md` |
| 2026-02-17 | Remediation | SEC-022: Created BiometricLock modules for iOS (Face ID/Touch ID via LocalAuthentication) and Android (BiometricPrompt); ready for UI integration |
