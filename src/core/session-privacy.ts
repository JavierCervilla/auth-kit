/**
 * Nothing about the client in `session`: no IP address and no user agent. `disableIpTracking` stops better-auth reading
 * the IP, but `createSession` still writes `""` instead of null, and 1.7.10 has no option for the user agent, so this
 * database hook nulls both columns on create and on renewal.
 */
export const withoutClientData = <T extends object>(session: T) =>
  Promise.resolve({ data: { ...session, ipAddress: null, userAgent: null } });
