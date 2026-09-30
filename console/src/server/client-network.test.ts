import { describe, expect, it } from "vitest";

import { clientNetwork } from "./events";

describe("clientNetwork (re-review N2)", () => {
  it.each([
    [null, "-"],
    ["local", "local"],
    ["203.0.113.9", "203.0.113.0/24"],
    ["203.0.113.250", "203.0.113.0/24"],
    ["::ffff:203.0.113.5", "203.0.113.0/24"],
    ["::ffff:cb00:7105", "203.0.113.0/24"],
    ["2001:db8:1:2::1", "2001:db8:1:2::/64"],
    ["2001:0DB8:0001:0002:ffff:0:0:9", "2001:db8:1:2::/64"],
    ["2001:db8::", "2001:db8:0:0::/64"],
    ["::1", "0:0:0:0::/64"],
  ])("%s -> %s", (addr, net) => {
    expect(clientNetwork(addr)).toBe(net);
  });
});
