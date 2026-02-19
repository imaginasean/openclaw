---
title: macOS App Sandbox Plan
---

# macOS App Sandbox Plan (SEC-020)

## Current State

The macOS OpenClaw app runs **without** App Sandbox entitlements. The gateway
process has unrestricted filesystem and network access.

## Why Not Sandboxed Yet

The gateway requires capabilities that are difficult to scope within a sandbox:

1. **Full network access** — listens on configurable ports, connects to
   arbitrary AI provider endpoints, Tailscale, and local devices.
2. **Filesystem access** — reads/writes `~/.openclaw/` config, session
   transcripts, plugin directories, and user workspace files.
3. **Process spawning** — runs shell commands on behalf of agents, manages
   Docker containers for sandboxed execution.
4. **AppleScript / Automation** — drives Terminal.app, browser, and other apps
   for agent actions.
5. **Keychain access** — stores TLS fingerprints and credentials.

## Incremental Path to Sandboxing

### Phase 1: Audit (current)
- Document all capabilities used.
- Identify the minimum entitlements required.

### Phase 2: Entitlements File
Create `OpenClaw.entitlements` with:
```xml
<key>com.apple.security.app-sandbox</key> <true/>
<key>com.apple.security.network.server</key> <true/>
<key>com.apple.security.network.client</key> <true/>
<key>com.apple.security.files.user-selected.read-write</key> <true/>
<key>com.apple.security.files.bookmarks.app-scope</key> <true/>
<key>com.apple.security.automation.apple-events</key> <true/>
<key>com.apple.security.temporary-exception.files.home-relative-path.read-write</key>
<array><string>/.openclaw/</string></array>
```

### Phase 3: Test
- Verify all features work under sandbox.
- Identify and fix breakages.
- File Apple Feedback for any needed exceptions.

### Phase 4: Ship
- Enable sandbox in release builds.
- Monitor crash reports for sandbox violations.

## Risk

Enabling sandbox may break Docker integration (docker socket access),
arbitrary shell execution, and AppleScript automation. Each must be tested
individually. This is a **high-effort, medium-risk** change.
