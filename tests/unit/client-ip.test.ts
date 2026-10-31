// Which IP address the send limit counts: the last `X-Forwarded-For` hop (or the `trustedProxyHops`-th from the right),
// IPv4 in full, IPv6 by its /64 and IPv4-mapped as IPv4. No header or unreadable: the shared `ip:none` bucket.
import { describe, expect, it } from "vitest";

import { clientIpSubject, NO_IP, normalizeIp } from "../../src/rate-limit/client-ip.js";

const xff = (value: string) => new Headers({ "x-forwarded-for": value });

describe("normalizeIp", () => {
  it("IPv4 in full", () => {
    expect(normalizeIp("203.0.113.7")).toBe("ip:v4:203.0.113.7");
    expect(normalizeIp(" 198.51.100.1 ")).toBe("ip:v4:198.51.100.1");
  });

  it("IPv6 by its /64: two in the same /64 match, another /64 does not", () => {
    const a = normalizeIp("2001:db8:1:2::1");
    expect(a).toBe("ip:v6:2001:db8:1:2::/64");
    expect(normalizeIp("2001:0DB8:0001:0002:ffff:eeee:dddd:9")).toBe(a);
    expect(normalizeIp("[2001:db8:1:2::abcd]")).toBe(a);
    expect(normalizeIp("2001:db8:1:3::1")).not.toBe(a);
    expect(normalizeIp("::1")).toBe("ip:v6:0:0:0:0::/64");
  });

  it("an IPv4-mapped IPv6 address counts as the IPv4", () => {
    expect(normalizeIp("::ffff:203.0.113.7")).toBe("ip:v4:203.0.113.7");
    expect(normalizeIp("::ffff:cb00:7107")).toBe("ip:v4:203.0.113.7");
  });

  it("what is unreadable is not an address", () => {
    for (const raw of [
      "",
      "unknown",
      "1.2.3",
      "1.2.3.256",
      "1.2.3.4:80",
      "2001:db8::1::2",
      "2001:db8:1:2:3:4:5:6:7",
      "gggg::1",
      "fe80::1%eth0",
      "12345::1",
    ]) {
      expect(normalizeIp(raw), raw).toBeNull();
    }
  });
});

describe("clientIpSubject", () => {
  it("counts the last hop: what the client writes on the left does not change the bucket", () => {
    const real = clientIpSubject(xff("203.0.113.7"), 1);
    expect(real).toBe("ip:v4:203.0.113.7");
    expect(clientIpSubject(xff("6.6.6.6, 203.0.113.7"), 1)).toBe(real);
    expect(clientIpSubject(xff("7.7.7.7,8.8.8.8,  203.0.113.7"), 1)).toBe(real);
  });

  it("with two trusted hops, the second from the right", () => {
    expect(clientIpSubject(xff("6.6.6.6, 203.0.113.7, 10.0.0.2"), 2)).toBe("ip:v4:203.0.113.7");
  });

  it("repeated headers read as one list, in order", () => {
    const headers = new Headers();
    headers.append("x-forwarded-for", "6.6.6.6");
    headers.append("x-forwarded-for", "203.0.113.7");
    expect(clientIpSubject(headers, 1)).toBe("ip:v4:203.0.113.7");
  });

  it("no header, unreadable, or fewer hops than trusted: the no-ip bucket", () => {
    expect(clientIpSubject(new Headers(), 1)).toBe(NO_IP);
    expect(clientIpSubject(xff("203.0.113.7, garbage"), 1)).toBe(NO_IP);
    expect(clientIpSubject(xff("203.0.113.7"), 2)).toBe(NO_IP);
    expect(clientIpSubject(xff(""), 1)).toBe(NO_IP);
  });
});
