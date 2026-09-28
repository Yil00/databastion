import { lookup as dnsLookup } from "node:dns/promises";
import { BlockList, isIP, isIPv4 } from "node:net";

/**
 * Outbound address policy of the notification senders (P3-C, SSRF defense). Only the worker opens
 * outbound connections (webhooks, SMTP); the web process only validates settings.
 *
 * Three classes:
 * - `forbidden`: never contacted, whatever the configuration: unspecified (`0.0.0.0/8`, `::`,
 *   which Linux routes to the local host), link-local (`169.254.0.0/16`, `fe80::/10`, including the
 *   cloud metadata endpoints `169.254.169.254` and `fd00:ec2::254`), multicast, broadcast and
 *   reserved ranges;
 * - `internal`: loopback, private (RFC 1918, ULA), shared (CGNAT), documentation / benchmark
 *   ranges, and the IPv6 transition prefixes that embed an IPv4 address (NAT64, 6to4, Teredo,
 *   IPv4-compatible): refused for webhooks unless `DATABASTION_ALERTING_INSECURE_DEV=1`; allowed
 *   for SMTP (mail relays are usually internal);
 * - `public`: everything else.
 * IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are classified as their IPv4 address.
 */
export type AddressClass = "public" | "internal" | "forbidden";

const forbidden = new BlockList();
const internal = new BlockList();

for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["169.254.0.0", 16],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  forbidden.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::", 128],
  ["fe80::", 10],
  ["ff00::", 8],
  ["fd00:ec2::254", 128],
] as const) {
  forbidden.addSubnet(net, prefix, "ipv6");
}
for (const [net, prefix] of [
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
] as const) {
  internal.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::1", 128],
  // IPv4-compatible (deprecated) addresses, `::a.b.c.d`.
  ["::", 96],
  ["fc00::", 7],
  ["2001:db8::", 32],
  ["100::", 64],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["2002::", 16],
  ["2001::", 32],
] as const) {
  internal.addSubnet(net, prefix, "ipv6");
}

const MAPPED_DOTTED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;
const MAPPED_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i;

/** `::ffff:a.b.c.d` / `::ffff:hhhh:hhhh` -> `a.b.c.d`; otherwise null. */
export function mappedIPv4(ip: string): string | null {
  const dotted = MAPPED_DOTTED.exec(ip);
  if (dotted?.[1] && isIPv4(dotted[1])) return dotted[1];
  const hex = MAPPED_HEX.exec(ip);
  if (hex?.[1] && hex[2]) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

/** Class of an IP literal; anything that is not an IP literal is `forbidden`. */
export function classifyAddress(ip: string): AddressClass {
  const bare = ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip;
  const family = isIP(bare);
  if (family === 0) return "forbidden";
  if (family === 6) {
    const v4 = mappedIPv4(bare);
    if (v4 !== null) return classifyAddress(v4);
  }
  const type = family === 4 ? "ipv4" : "ipv6";
  if (forbidden.check(bare, type)) return "forbidden";
  if (internal.check(bare, type)) return "internal";
  return "public";
}

export type Resolver = (host: string) => Promise<{ address: string; family: number }[]>;

const systemResolver: Resolver = (host) => dnsLookup(host, { all: true, verbatim: true });

export type ResolveOutcome =
  | { ok: true; address: string; family: 4 | 6 }
  | { ok: false; code: "dns_failed" | "address_forbidden" | "address_internal"; retryable: boolean };

/**
 * Resolves `host` for an outbound connection and applies the address policy to EVERY resolved
 * address (a name resolving to one public and one internal address is refused: no mixed-record
 * tricks). The caller connects to the returned address only (pinned: no second resolution between
 * the check and the connection, so DNS rebinding cannot swap it).
 */
export async function resolveOutbound(
  host: string,
  opts: { allowInternal: boolean; resolver?: Resolver },
): Promise<ResolveOutcome> {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  let addresses: { address: string; family: number }[];
  if (isIP(bare) !== 0) {
    addresses = [{ address: bare, family: isIP(bare) }];
  } else {
    try {
      addresses = await (opts.resolver ?? systemResolver)(bare);
    } catch {
      return { ok: false, code: "dns_failed", retryable: true };
    }
  }
  if (addresses.length === 0) return { ok: false, code: "dns_failed", retryable: true };
  let internalSeen = false;
  for (const a of addresses) {
    const cls = classifyAddress(a.address);
    if (cls === "forbidden") return { ok: false, code: "address_forbidden", retryable: false };
    if (cls === "internal") internalSeen = true;
  }
  if (internalSeen && !opts.allowInternal) return { ok: false, code: "address_internal", retryable: false };
  const first = addresses[0] as { address: string; family: number };
  return { ok: true, address: first.address, family: isIP(first.address) === 6 ? 6 : 4 };
}

/**
 * `lookup` option for `net` / `tls` / `http(s)` that always answers the pinned address (handles
 * both the single-address and the `all: true` call styles of Node's socket code).
 */
export function pinnedLookup(address: string, family: 4 | 6) {
  return (
    _hostname: string,
    options: { all?: boolean } | number | undefined,
    callback: (err: NodeJS.ErrnoException | null, address: string | { address: string; family: number }[], family?: number) => void,
  ): void => {
    if (typeof options === "object" && options?.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}
