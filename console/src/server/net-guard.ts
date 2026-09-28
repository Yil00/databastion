import { lookup as dnsLookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

/**
 * Outbound address policy of the notification senders (P3-C, SSRF defense). Only the worker opens
 * outbound connections (webhooks, SMTP); the web process only validates settings.
 *
 * Three classes (from the IANA IPv4 / IPv6 special-purpose address registries):
 * - `forbidden`: never contacted, whatever the configuration or the sender: unspecified
 *   (`0.0.0.0/8`, `::`, which Linux routes to the local host), link-local (`169.254.0.0/16`,
 *   `fe80::/10`, including the cloud metadata endpoints `169.254.169.254` and `fd00:ec2::254`),
 *   multicast, broadcast and reserved (`240.0.0.0/4`);
 * - `internal`: loopback, private (RFC 1918, ULA, deprecated site-local `fec0::/10`), shared
 *   (CGNAT), IETF protocol assignments (`192.0.0.0/24`, `2001::/23`: ORCHID, AMT, AS112, DRIP…),
 *   AS112 / AMT / 6to4-relay anycast, documentation (`192.0.2.0/24`, `198.51.100.0/24`,
 *   `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`), benchmarking, discard / dummy prefixes, SRv6
 *   SIDs (`5f00::/16`) and the IPv6 transition prefixes: refused for webhooks unless
 *   `DATABASTION_ALERTING_INSECURE_DEV=1`; allowed for SMTP (mail relays are usually internal);
 * - `public`: everything else.
 * L2: an IPv6 address that embeds an IPv4 address (IPv4-mapped `::ffff:0:0/96`, IPv4-translated
 * `::ffff:0:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo
 * `2001::/32` with its server and its inverted client address) gets the STRICTER of the prefix
 * class and the class of every embedded IPv4 address: `64:ff9b::a9fe:a9fe` (metadata through NAT64)
 * is forbidden, even for SMTP.
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
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
] as const) {
  internal.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::1", 128],
  // IPv4-compatible (deprecated) and IPv4-translated addresses. IPv4-mapped `::ffff:0:0/96` is
  // not listed: BlockList compares IPv4 addresses to IPv6 rules in that form (every IPv4 address
  // would match); mapped addresses are classified by their embedded IPv4 address instead.
  ["::", 96],
  ["::ffff:0:0:0", 96],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["100:0:0:1::", 64],
  // IETF protocol assignments: Teredo, benchmarking, AMT, AS112, ORCHID(v2), DRIP…
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["2620:4f:8000::", 48],
  ["3fff::", 20],
  ["5f00::", 16],
  ["fc00::", 7],
  ["fec0::", 10],
] as const) {
  internal.addSubnet(net, prefix, "ipv6");
}

/** The 8 16-bit groups of an IPv6 literal (with or without an embedded dotted quad); null if invalid. */
export function ipv6Groups(ip: string): number[] | null {
  if (isIP(ip) !== 6) return null;
  let text = ip.toLowerCase();
  const zone = text.indexOf("%");
  if (zone >= 0) text = text.slice(0, zone);
  const dotted = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  let tail: number[] = [];
  if (dotted?.[1]) {
    const o = dotted[1].split(".").map(Number);
    tail = [((o[0] ?? 0) << 8) | (o[1] ?? 0), ((o[2] ?? 0) << 8) | (o[3] ?? 0)];
    text = text.slice(0, -dotted[1].length);
    if (text.endsWith(":") && !text.endsWith("::")) text = text.slice(0, -1);
  }
  const parse = (part: string) => (part === "" ? [] : part.split(":").map((h) => parseInt(h, 16)));
  let groups: number[];
  if (text.includes("::")) {
    const [head = "", rest = ""] = text.split("::");
    const h = parse(head);
    const t = [...parse(rest), ...tail];
    groups = [...h, ...Array(8 - h.length - t.length).fill(0), ...t];
  } else {
    groups = [...parse(text), ...tail];
  }
  return groups.length === 8 && groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff) ? groups : null;
}

const v4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/**
 * IPv4 addresses embedded in an IPv6 address by the transition mechanisms (see the class doc);
 * empty for any other address.
 */
export function embeddedIPv4(ip: string): string[] {
  const g = ipv6Groups(ip);
  if (!g) return [];
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [number, number, number, number, number, number, number, number];
  const zero = (...xs: number[]) => xs.every((x) => x === 0);
  // IPv4-mapped ::ffff:a.b.c.d, IPv4-translated ::ffff:0:a.b.c.d, IPv4-compatible ::a.b.c.d.
  if (zero(g0, g1, g2, g3) && g4 === 0 && g5 === 0xffff) return [v4(g6, g7)];
  if (zero(g0, g1, g2, g3) && g4 === 0xffff && g5 === 0) return [v4(g6, g7)];
  if (zero(g0, g1, g2, g3, g4, g5) && !(g6 === 0 && (g7 === 0 || g7 === 1))) return [v4(g6, g7)];
  // NAT64 well-known prefix 64:ff9b::/96.
  if (g0 === 0x64 && g1 === 0xff9b && zero(g2, g3, g4, g5)) return [v4(g6, g7)];
  // 6to4 2002:AABB:CCDD::/48.
  if (g0 === 0x2002) return [v4(g1, g2)];
  // Teredo 2001:0000:<server v4>:<flags>:<port>:<client v4 inverted>.
  if (g0 === 0x2001 && g1 === 0) return [v4(g2, g3), v4(g6 ^ 0xffff, g7 ^ 0xffff)];
  return [];
}

/** `::ffff:a.b.c.d` / `::ffff:hhhh:hhhh` -> `a.b.c.d`; otherwise null. */
export function mappedIPv4(ip: string): string | null {
  const g = ipv6Groups(ip);
  if (!g || !g.slice(0, 5).every((x) => x === 0) || g[5] !== 0xffff) return null;
  return v4(g[6] as number, g[7] as number);
}

const RANK: Record<AddressClass, number> = { public: 0, internal: 1, forbidden: 2 };
const stricter = (a: AddressClass, b: AddressClass): AddressClass => (RANK[b] > RANK[a] ? b : a);

function classifyBare(ip: string, family: 4 | 6): AddressClass {
  const type = family === 4 ? "ipv4" : "ipv6";
  if (forbidden.check(ip, type)) return "forbidden";
  if (internal.check(ip, type)) return "internal";
  return "public";
}

/** Class of an IP literal; anything that is not an IP literal is `forbidden`. */
export function classifyAddress(ip: string): AddressClass {
  const bare = ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip;
  const family = isIP(bare);
  if (family === 0) return "forbidden";
  if (family === 4) return classifyBare(bare, 4);
  // `::` and `::1` first (they would otherwise read as IPv4-compatible 0.0.0.0 / 0.0.0.1).
  let cls = classifyBare(bare, 6);
  for (const embedded of embeddedIPv4(bare)) cls = stricter(cls, classifyBare(embedded, 4));
  return cls;
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
