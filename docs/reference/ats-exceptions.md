---
title: ATS Exception Rationale
---

# App Transport Security (ATS) Exceptions

Both the iOS and macOS OpenClaw apps require ATS exceptions to connect to
local and Tailscale-based gateways. This document records the rationale for
each exception.

## `NSAllowsArbitraryLoadsInWebContent`

**Scope:** WKWebView only (does not affect URLSession or other networking).

**Rationale:** The gateway control UI is served over HTTP on the local network
(typically `http://localhost:18789` or a LAN IP). WKWebView must be able to
load this content without HTTPS.

## `NSExceptionDomains`

### `100.100.100.100`

**Scope:** macOS only. `NSIncludesSubdomains: false` (single IP, no subdomain
wildcard).

**Rationale:** This is the Tailscale CGNAT control plane address. When a user
connects to a gateway via Tailscale direct IP (no DNS), the connection uses
HTTP because the self-signed gateway certificate is pinned by fingerprint, not
by hostname-verified TLS.

### `openclaw.local`

**Scope:** macOS only. `NSIncludesSubdomains: true` (covers mDNS names like
`My-Mac.openclaw.local`).

**Rationale:** Local network gateway discovery uses mDNS (Bonjour, service type
`_openclaw-gw._tcp`). Discovered gateways are accessed over HTTP on the LAN.

## iOS Notes

iOS uses only `NSAllowsArbitraryLoadsInWebContent` — no domain-specific
exceptions. Local connections are handled via the mDNS-discovered gateway, and
Tailscale connections use the TLS fingerprint pinning path.

## Review Cadence

Review these exceptions quarterly. If a narrower scope becomes possible (e.g.,
HTTPS-by-default for local gateways), tighten accordingly.
