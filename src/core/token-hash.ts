import { createHash } from "node:crypto";

/**
 * What the magic link and the email code store in `verification` instead of the secret: its SHA-256 in base64url, no
 * padding. Computed here (not with the plugins' built-in "hashed") so the guest-to-account guard can find the row.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}
