import { describe, expect, it } from "vitest";

import { classifyAddress, mappedIPv4, pinnedLookup, resolveOutbound } from "./net-guard";

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
    ["example.com", "forbidden"],
    ["", "forbidden"],
  ])("%s is %s", (ip, cls) => {
    expect(classifyAddress(ip)).toBe(cls);
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
