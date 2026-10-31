/**
 * Which IP address the send limit counts. Returns a normalised «subject» that is then keyed with an HMAC (limiter.ts):
 * neither this text nor the IP address is stored or logged.
 *
 * - The address is the `trustedProxyHops`-th entry from the RIGHT of `X-Forwarded-For` (by default the last one, the
 *   one the reverse proxy appends). Never the leftmost, which the client writes.
 * - IPv4 in full; IPv6 by its /64 prefix; an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as the IPv4.
 * - No header, unreadable, or fewer entries than trusted hops: the shared bucket `ip:none` (fails closed). With fewer
 *   entries than hops the request did not cross every expected proxy, and the entry left could be the client's own.
 */

export const NO_IP = "ip:none";

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;
const MAX_OCTET = 255;
const IPV6_GROUPS = 8;
const PREFIX_64_GROUPS = 4;
const IPV4_MAPPED_MARKER = 0xffff;

function ipv4Octets(raw: string): number[] | null {
  const match = IPV4.exec(raw);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.every((o) => o <= MAX_OCTET) ? octets : null;
}

function hexGroups(part: string): number[] | null {
  if (part === "") return [];
  const groups = part.split(":");
  if (!groups.every((g) => HEX_GROUP.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

/** An IPv4 at the end of an IPv6 (`::ffff:1.2.3.4`) becomes its two hex groups; `null` if it is malformed. */
function inlineEmbeddedIpv4(text: string): string | null {
  const lastColon = text.lastIndexOf(":");
  const last = text.slice(lastColon + 1);
  if (!last.includes(".")) return text;
  const octets = ipv4Octets(last);
  if (!octets) return null;
  const [a = 0, b = 0, c = 0, d = 0] = octets;
  return `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
}

/** The eight 16-bit groups of an IPv6 address, or `null` if it is not one. */
function ipv6Groups(raw: string): number[] | null {
  const text = inlineEmbeddedIpv4(raw);
  if (text === null) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = hexGroups(halves[0] ?? "");
  const rest = halves.length === 2 ? hexGroups(halves[1] ?? "") : [];
  if (!head || !rest) return null;
  const explicit = head.length + rest.length;
  if (halves.length === 1) return explicit === IPV6_GROUPS ? head : null;
  if (explicit > IPV6_GROUPS - 1) return null;
  return [...head, ...Array<number>(IPV6_GROUPS - explicit).fill(0), ...rest];
}

function mappedIpv4(groups: readonly number[]): string | null {
  const mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === IPV4_MAPPED_MARKER;
  if (!mapped) return null;
  const [hi = 0, lo = 0] = groups.slice(6);
  return `ip:v4:${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

/** The subject of an IP address (`ip:v4:…` or `ip:v6:…/64`), or `null` if it is not a readable address. */
export function normalizeIp(raw: string): string | null {
  let text = raw.trim();
  if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
  const v4 = ipv4Octets(text);
  if (v4) return `ip:v4:${v4.join(".")}`;
  const groups = ipv6Groups(text);
  if (!groups) return null;
  const prefix = groups
    .slice(0, PREFIX_64_GROUPS)
    .map((g) => g.toString(16))
    .join(":");
  return mappedIpv4(groups) ?? `ip:v6:${prefix}::/64`;
}

/** The client's subject from `X-Forwarded-For` and the trusted hops; `ip:none` if it cannot be known. */
export function clientIpSubject(headers: Headers, trustedProxyHops: number): string {
  // `Headers.get` joins repeated headers with ", ", in order: the list is the same.
  const entries = (headers.get("x-forwarded-for") ?? "").split(",").map((e) => e.trim());
  const entry = entries.length >= trustedProxyHops ? entries[entries.length - trustedProxyHops] : undefined;
  return (entry ? normalizeIp(entry) : null) ?? NO_IP;
}
