/**
 * SEC-002: Gateway password hashing using Node.js built-in scrypt.
 *
 * Hashed passwords are stored as: $scrypt$N=16384,r=8,p=1$<base64-salt>$<base64-hash>
 * Plaintext passwords (legacy) are detected by the absence of the $scrypt$ prefix.
 */

import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const SCRYPT_PREFIX = "$scrypt$";
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 64;
const SALT_LENGTH = 32;

export function isHashedPassword(value: string): boolean {
  return value.startsWith(SCRYPT_PREFIX);
}

export async function hashPassword(plaintext: string): Promise<string> {
  const salt = randomBytes(SALT_LENGTH);
  const derived = await scryptAsync(plaintext, salt, KEY_LENGTH);
  const params = `N=${SCRYPT_N},r=${SCRYPT_R},p=${SCRYPT_P}`;
  return `${SCRYPT_PREFIX}${params}$${salt.toString("base64")}$${derived.toString("base64")}`;
}

export async function verifyPassword(plaintext: string, hash: string): Promise<boolean> {
  if (!isHashedPassword(hash)) {
    return false;
  }
  const parts = hash.slice(SCRYPT_PREFIX.length).split("$");
  if (parts.length !== 3) {
    return false;
  }
  const [paramStr, saltB64, hashB64] = parts;
  if (!paramStr || !saltB64 || !hashB64) {
    return false;
  }

  const params = parseScryptParams(paramStr);
  if (!params) {
    return false;
  }

  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(saltB64, "base64");
    expected = Buffer.from(hashB64, "base64");
  } catch {
    return false;
  }

  if (expected.length === 0 || salt.length === 0) {
    return false;
  }

  const derived = await scryptAsync(plaintext, salt, expected.length, params);
  if (derived.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(derived, expected);
}

function parseScryptParams(
  raw: string,
): { N: number; r: number; p: number } | null {
  const map = new Map<string, number>();
  for (const part of raw.split(",")) {
    const [key, val] = part.split("=");
    if (!key || !val) {
      return null;
    }
    const num = Number.parseInt(val, 10);
    if (!Number.isFinite(num) || num <= 0) {
      return null;
    }
    map.set(key, num);
  }
  const N = map.get("N");
  const r = map.get("r");
  const p = map.get("p");
  if (!N || !r || !p) {
    return null;
  }
  return { N, r, p };
}

function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  params?: { N: number; r: number; p: number },
): Promise<Buffer> {
  const opts = {
    N: params?.N ?? SCRYPT_N,
    r: params?.r ?? SCRYPT_R,
    p: params?.p ?? SCRYPT_P,
    maxmem: 256 * 1024 * 1024,
  };
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, opts, (err, derivedKey) => {
      if (err) {
        reject(err);
      } else {
        resolve(derivedKey);
      }
    });
  });
}
