import { describe, expect, it } from "vitest";

import { classifyAddress, embeddedIPv4, ipv6Groups, mappedIPv4, pinnedLookup, resolveOutbound } from "./net-guard";

describe("outbound address policy (SSRF)", () => {
  it.each([
    ["8.8.8.8", "public"],
    ["2606:4700::1111", "public"],
    ["127.0.0.1", "internal"],
    ["127.9.9.9", "internal"],
    ["10.1.2.3", "internal"],
    ["172.16.0.1", "internal"],
    ["172.31.255.255", "internal"],
    ["172.32.0.1", "public"],
    ["192.168.1.1", "internal"],
    ["100.64.0.1", "internal"],
    ["198.18.0.1", "internal"],
    ["::1", "internal"],
    ["fc00::1", "internal"],
    ["fd12:3456::1", "internal"],
    ["64:ff9b::a00:1", "internal"],
    ["2002:a00:1::1", "internal"],
    ["::10.0.0.1", "internal"],
    ["0.0.0.0", "forbidden"],
    ["0.1.2.3", "forbidden"],
    ["169.254.169.254", "forbidden"],
    ["169.254.0.1", "forbidden"],
    ["fe80::1", "forbidden"],
    ["fd00:ec2::254", "forbidden"],
    ["::", "forbidden"],
    ["224.0.0.1", "forbidden"],
    ["255.255.255.255", "forbidden"],
    ["ff02::1", "forbidden"],
    ["::ffff:169.254.169.254", "forbidden"],
    ["::ffff:a9fe:a9fe", "forbidden"],
    ["::ffff:127.0.0.1", "internal"],
    ["::ffff:7f00:1", "internal"],
    ["::ffff:8.8.8.8", "public"],
    ["[::1]", "internal"],
    // L2: more special-purpose ranges (IANA registries).
    ["192.31.196.1", "internal"],
    ["192.52.193.1", "internal"],
    ["192.175.48.1", "internal"],
    ["192.0.0.9", "internal"],
    ["fec0::1", "internal"],
    ["3fff::1", "internal"],
    ["3fff:fff::1", "internal"],
    ["5f00::1", "internal"],
    ["2001:10::1", "internal"],
    ["2001:20::1", "internal"],
    ["2001:2::1", "internal"],
    ["2620:4f:8000::1", "internal"],
    ["100:0:0:1::1", "internal"],
    ["2001:200::1", "public"],
    // L2: embedded IPv4 gets the stricter class.
    ["64:ff9b::a9fe:a9fe", "forbidden"],
    ["64:ff9b::169.254.169.254", "forbidden"],
    ["64:ff9b::808:808", "internal"],
    ["::169.254.169.254", "forbidden"],
    ["::a9fe:a9fe", "forbidden"],
    ["::ffff:0:a9fe:a9fe", "forbidden"],
    ["::ffff:0:10.0.0.1", "internal"],
    ["2002:a9fe:a9fe::1", "forbidden"],
    ["2002:808:808::1", "internal"],
    // Teredo: server 65.54.227.120, client 169.254.169.254 (inverted: 5601:5601).
    ["2001:0:4136:e378:8000:63bf:5601:5601", "forbidden"],
    // Teredo with a metadata server address.
    ["2001:0:a9fe:a9fe:8000:63bf:f7f7:f7f7", "forbidden"],
    ["2001:0:4136:e378:8000:63bf:f7f7:f7f7", "internal"],
    ["example.com", "forbidden"],
    ["", "forbidden"],
  ])("%s is %s", (ip, cls) => {
    expect(classifyAddress(ip)).toBe(cls);
  });

  it("parses IPv6 groups and extracts every embedded IPv4 address", () => {
    expect(ipv6Groups("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups("64:ff9b::1.2.3.4")).toEqual([0x64, 0xff9b, 0, 0, 0, 0, 0x102, 0x304]);
    expect(ipv6Groups("1.2.3.4")).toBeNull();
    expect(embeddedIPv4("64:ff9b::a00:1")).toEqual(["10.0.0.1"]);
    expect(embeddedIPv4("2002:a00:1::")).toEqual(["10.0.0.1"]);
    expect(embeddedIPv4("2001:0:4136:e378:8000:63bf:3fff:fdd2")).toEqual(["65.54.227.120", "192.0.2.45"]);
    expect(embeddedIPv4("::ffff:0:1.2.3.4")).toEqual(["1.2.3.4"]);
    expect(embeddedIPv4("::1")).toEqual([]);
    expect(embeddedIPv4("2606:4700::1111")).toEqual([]);
  });

  it("extracts mapped IPv4 addresses in both notations", () => {
    expect(mappedIPv4("::ffff:10.0.0.1")).toBe("10.0.0.1");
    expect(mappedIPv4("::FFFF:0a00:0001")).toBe("10.0.0.1");
    expect(mappedIPv4("::1")).toBeNull();
  });

  const resolver = (map: Record<string, string[]>) => async (host: string) => {
    const addrs = map[host];
    if (!addrs) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    return addrs.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
  };

  it("checks every resolved address and pins the first one", async () => {
    const r = resolver({
      "ok.example": ["93.184.216.34", "2606:2800:220:1::1"],
      "mixed.example": ["93.184.216.34", "10.0.0.5"],
      "meta.example": ["169.254.169.254"],
      "lan.example": ["192.168.0.10"],
    });
    expect(await resolveOutbound("ok.example", { allowInternal: false, resolver: r })).toEqual({ ok: true, address: "93.184.216.34", family: 4 });
    expect(await resolveOutbound("mixed.example", { allowInternal: false, resolver: r })).toMatchObject({ ok: false, code: "address_internal" });
    // The dev flag allows internal addresses, never metadata / link-local ones.
    expect(await resolveOutbound("lan.example", { allowInternal: true, resolver: r })).toMatchObject({ ok: true, address: "192.168.0.10" });
    expect(await resolveOutbound("meta.example", { allowInternal: true, resolver: r })).toMatchObject({ ok: false, code: "address_forbidden", retryable: false });
    expect(await resolveOutbound("missing.example", { allowInternal: false, resolver: r })).toMatchObject({ ok: false, code: "dns_failed", retryable: true });
    // IP literals are not resolved.
    expect(await resolveOutbound("127.0.0.1", { allowInternal: false, resolver: r })).toMatchObject({ ok: false, code: "address_internal" });
    expect(await resolveOutbound("[::1]", { allowInternal: true, resolver: r })).toMatchObject({ ok: true, address: "::1", family: 6 });
    // Metadata through NAT64: forbidden even when internal addresses are allowed (SMTP).
    const nat64 = resolver({ "relay.example": ["64:ff9b::a9fe:a9fe"] });
    expect(await resolveOutbound("relay.example", { allowInternal: true, resolver: nat64 })).toMatchObject({ ok: false, code: "address_forbidden" });
  });

  it("the pinned lookup answers the vetted address in both call styles", () => {
    const lookup = pinnedLookup("93.184.216.34", 4);
    let single: unknown[] = [];
    lookup("evil.example", {}, (...args) => (single = args));
    expect(single).toEqual([null, "93.184.216.34", 4]);
    let all: unknown[] = [];
    lookup("evil.example", { all: true }, (...args) => (all = args));
    expect(all).toEqual([null, [{ address: "93.184.216.34", family: 4 }]]);
  });
});
