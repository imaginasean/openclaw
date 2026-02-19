import fs from "node:fs";
import path from "node:path";
import {
  decryptCredential,
  encryptCredential,
  isEncrypted,
} from "../security/credential-encryption.js";

const BLOCKED_PROTO_KEYS = new Set(["__proto__", "prototype", "constructor"]);

/**
 * JSON reviver that strips prototype-pollution keys (`__proto__`, `prototype`,
 * `constructor`) from any parsed object. Use this for any JSON originating from
 * disk, network, or other untrusted sources.
 */
export function safeJsonReviver(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const k of Object.keys(value as Record<string, unknown>)) {
      if (BLOCKED_PROTO_KEYS.has(k)) {
        delete (value as Record<string, unknown>)[k];
      }
    }
  }
  return value;
}

/**
 * Drop-in replacement for `JSON.parse` that rejects prototype-pollution keys.
 */
export function safeJsonParse(text: string): unknown {
  return JSON.parse(text, safeJsonReviver) as unknown;
}

export function loadJsonFile(pathname: string): unknown {
  try {
    if (!fs.existsSync(pathname)) {
      return undefined;
    }
    const raw = fs.readFileSync(pathname, "utf8");
    return safeJsonParse(raw);
  } catch {
    return undefined;
  }
}

export function saveJsonFile(pathname: string, data: unknown) {
  const dir = path.dirname(pathname);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(pathname, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  fs.chmodSync(pathname, 0o600);
}

// SEC-001: Encrypted file variants — lazily import to avoid circular deps.

/**
 * Load a JSON file that may be encrypted at rest.
 * Transparently handles both encrypted (enc:v1:…) and legacy plaintext files.
 */
export function loadEncryptedJsonFile(pathname: string): unknown {
  try {
    if (!fs.existsSync(pathname)) {
      return undefined;
    }
    const raw = fs.readFileSync(pathname, "utf8").trim();
    if (!raw) {
      return undefined;
    }
    if (isEncrypted(raw)) {
      const json = decryptCredential(raw);
      return safeJsonParse(json);
    }
    return safeJsonParse(raw);
  } catch {
    return undefined;
  }
}

/**
 * Save a JSON file with AES-256-GCM encryption at rest.
 */
export function saveEncryptedJsonFile(pathname: string, data: unknown) {
  const dir = path.dirname(pathname);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const json = JSON.stringify(data, null, 2);
  const encrypted = encryptCredential(json);
  fs.writeFileSync(pathname, `${encrypted}\n`, "utf8");
  fs.chmodSync(pathname, 0o600);
}
