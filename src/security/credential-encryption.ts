/**
 * SEC-001: Encryption-at-rest for credential files.
 *
 * Derives a machine-bound encryption key from the hostname + username + a
 * stable per-installation salt persisted at ~/.openclaw/.enc-salt.
 * Uses AES-256-GCM for authenticated encryption.
 *
 * This is defense-in-depth — it protects against casual disk access and
 * backup exposure but not against a determined attacker with code execution
 * on the same machine (they can reproduce the key derivation inputs).
 * For stronger guarantees, integrate with OS keychain (macOS Keychain,
 * Windows DPAPI, Linux Secret Service).
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CONFIG_DIR } from "../utils.js";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const HEADER = "enc:v1:";

const SALT_FILE = path.join(CONFIG_DIR, ".enc-salt");

function getOrCreateSalt(): Buffer {
  try {
    if (fs.existsSync(SALT_FILE)) {
      const raw = fs.readFileSync(SALT_FILE);
      if (raw.length === SALT_LENGTH) {
        return raw;
      }
    }
  } catch {
    // Fall through to create new salt.
  }
  const salt = randomBytes(SALT_LENGTH);
  try {
    fs.mkdirSync(path.dirname(SALT_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(SALT_FILE, salt, { mode: 0o600 });
  } catch {
    // If we can't persist, use ephemeral salt (encryption will work for
    // the current session but data won't be decryptable after restart).
  }
  return salt;
}

function deriveMachineKey(): Buffer {
  const salt = getOrCreateSalt();
  const identity = `${os.hostname()}:${os.userInfo().username}`;
  return scryptSync(identity, salt, KEY_LENGTH);
}

export function isEncrypted(data: string): boolean {
  return data.startsWith(HEADER);
}

export function encryptCredential(plaintext: string): string {
  const key = deriveMachineKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const payload = Buffer.concat([iv, authTag, encrypted]);
  return HEADER + payload.toString("base64");
}

export function decryptCredential(encoded: string): string {
  if (!encoded.startsWith(HEADER)) {
    throw new Error("Not an encrypted credential (missing header)");
  }
  const payload = Buffer.from(encoded.slice(HEADER.length), "base64");
  if (payload.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new Error("Encrypted credential payload too short");
  }
  const iv = payload.subarray(0, IV_LENGTH);
  const authTag = payload.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = payload.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

  const key = deriveMachineKey();
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
}

/**
 * Encrypt a JSON value for storage. Returns the encrypted string.
 */
export function encryptJsonValue(value: unknown): string {
  return encryptCredential(JSON.stringify(value));
}

/**
 * Decrypt an encrypted JSON string, returning the parsed value.
 * If the input is not encrypted (legacy plaintext), parse it directly.
 */
export function decryptJsonValue(encoded: string): unknown {
  if (isEncrypted(encoded)) {
    return JSON.parse(decryptCredential(encoded)) as unknown;
  }
  return JSON.parse(encoded) as unknown;
}
