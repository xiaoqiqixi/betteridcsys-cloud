import { describe, expect, it } from "vitest";
import { auditNames } from "../src/format";
import {
  ipv4,
  matchesNetworkIntent,
  networkID,
  networkPage,
  validLease,
  validPool,
  validVPC,
} from "../src/api/network";

const vpc = {
  id: "1".repeat(32),
  owner_ref: "2".repeat(32),
  node_id: "node-a",
  name: "客户私有网络",
  cidr: "10.20.0.0/24",
  vlan_id: 42,
  state: "planned",
  created_at: "2026-10-23T00:00:00.123456Z",
};
const pool = {
  id: "3".repeat(32),
  node_id: vpc.node_id,
  vpc_id: vpc.id,
  name: "客户地址池",
  cidr: vpc.cidr,
  gateway: "10.20.0.1",
  addresses: ["10.20.0.2", "10.20.0.3"],
  enabled: true,
};
const lease = {
  id: "4".repeat(32),
  pool_id: pool.id,
  vpc_id: vpc.id,
  node_id: vpc.node_id,
  instance_id: "a".repeat(32),
  owner_ref: vpc.owner_ref,
  address: "10.20.0.2",
  state: "reserved",
  created_at: vpc.created_at,
};
const vpcBody = {
  owner_ref: vpc.owner_ref,
  node_id: vpc.node_id,
  name: vpc.name,
  cidr: vpc.cidr,
  vlan_id: vpc.vlan_id,
};
const poolBody = {
  node_id: pool.node_id,
  vpc_id: pool.vpc_id,
  name: pool.name,
  cidr: pool.cidr,
  gateway: pool.gateway,
  addresses: pool.addresses,
  enabled: true,
};
const leaseBody = {
  pool_id: lease.pool_id,
  instance_id: lease.instance_id,
  owner_ref: lease.owner_ref,
  address: lease.address,
};

describe("network DTOs describe plans and reservations, never connectivity", () => {
  it("translates network audit actions without claiming connectivity or application", () => {
    expect(auditNames["network.vpc.planned"]).toEqual([
      "私有网络已规划",
      "Private network planned",
    ]);
    expect(auditNames["network.pool.created"]).toEqual([
      "IP 地址池已创建",
      "IP pool created",
    ]);
    expect(auditNames["network.lease.reserved"]).toEqual([
      "IP 地址已预留",
      "IP address reserved",
    ]);
  });
  it("accepts each complete exact-state record and only its matching list", () => {
    expect(validVPC(vpc)).toBe(true);
    expect(validPool(pool)).toBe(true);
    expect(validLease(lease)).toBe(true);
    expect(networkPage("vpcs")({ items: [vpc], next_cursor: null })).toBe(true);
    expect(networkPage("pools")({ items: [pool], next_cursor: pool.id })).toBe(
      true,
    );
    expect(networkPage("leases")({ items: [lease], next_cursor: null })).toBe(
      true,
    );
    expect(networkPage("vpcs")({ items: [pool], next_cursor: null })).toBe(
      false,
    );
    expect(networkPage("pools")({ items: [lease], next_cursor: null })).toBe(
      false,
    );
  });
  it.each(["connected", "active", "succeeded", "Planned", "Reserved"])(
    "does not accept guessed live state %s",
    (state) => {
      expect(validVPC({ ...vpc, state })).toBe(false);
      expect(validLease({ ...lease, state })).toBe(false);
    },
  );
  for (const [label, value, guard] of [
    ["vpc", vpc, validVPC],
    ["pool", pool, validPool],
    ["lease", lease, validLease],
  ] as const)
    it.each(Object.keys(value))(`${label} requires field %s`, (key) => {
      const copy: Record<string, unknown> = { ...value };
      delete copy[key];
      expect(guard(copy)).toBe(false);
    });
  it.each(["1".repeat(31), "A".repeat(32), "1".repeat(33), "", "../node"])(
    "rejects unsafe ID %j",
    (id) => {
      expect(networkID(id)).toBe(false);
      expect(validVPC({ ...vpc, id })).toBe(false);
    },
  );
  it.each([
    "01.2.3.4",
    "256.0.0.1",
    "1.2.3",
    "1.2.3.4.5",
    "1.2.3.-1",
    " 1.2.3.4",
    "::1",
  ])("rejects noncanonical IPv4 %s", (address) =>
    expect(ipv4(address)).toBe(false),
  );
  it("rejects duplicate/empty pool addresses, malformed VLAN and non-boolean flags", () => {
    expect(validPool({ ...pool, addresses: [] })).toBe(false);
    expect(validPool({ ...pool, addresses: ["10.20.0.2", "10.20.0.2"] })).toBe(
      false,
    );
    expect(validPool({ ...pool, enabled: "true" })).toBe(false);
    for (const vlan_id of [0, 4095, 1.5, "42", null])
      expect(validVPC({ ...vpc, vlan_id })).toBe(false);
  });
  it.each(["", "opaque-but-not-an-id", "F".repeat(32), "a".repeat(31)])(
    "rejects malformed network next_cursor %j",
    (next_cursor) => {
      expect(networkPage("vpcs")({ items: [vpc], next_cursor })).toBe(false);
    },
  );
});

describe("read-after-lost-ACK binds the complete original intent", () => {
  it("binds every VPC field and original key", () => {
    expect(matchesNetworkIntent("vpcs", vpc, vpc.id, vpcBody)).toBe(true);
    expect(matchesNetworkIntent("vpcs", vpc, "f".repeat(32), vpcBody)).toBe(
      false,
    );
    for (const [field, value] of Object.entries(vpcBody)) {
      const changed = {
        ...vpcBody,
        [field]: typeof value === "number" ? value + 1 : `${value}-changed`,
      };
      expect(matchesNetworkIntent("vpcs", vpc, vpc.id, changed), field).toBe(
        false,
      );
    }
  });
  it("treats pool address order as a set but never a changed address/member or field", () => {
    expect(
      matchesNetworkIntent("pools", pool, pool.id, {
        ...poolBody,
        addresses: [...pool.addresses].reverse(),
      }),
    ).toBe(true);
    expect(
      matchesNetworkIntent("pools", pool, pool.id, {
        ...poolBody,
        addresses: ["10.20.0.4", "10.20.0.3"],
      }),
    ).toBe(false);
    expect(
      matchesNetworkIntent("pools", pool, pool.id, {
        ...poolBody,
        enabled: false,
      }),
    ).toBe(false);
    expect(
      matchesNetworkIntent("pools", pool, pool.id, {
        ...poolBody,
        node_id: "other",
      }),
    ).toBe(false);
  });
  it("permits a server-selected address only when the original lease intent requested an empty address", () => {
    expect(matchesNetworkIntent("leases", lease, lease.id, leaseBody)).toBe(
      true,
    );
    expect(
      matchesNetworkIntent("leases", lease, lease.id, {
        ...leaseBody,
        address: "",
      }),
    ).toBe(true);
    expect(
      matchesNetworkIntent("leases", lease, lease.id, {
        ...leaseBody,
        address: "10.20.0.9",
      }),
    ).toBe(false);
    expect(
      matchesNetworkIntent("leases", lease, lease.id, {
        ...leaseBody,
        owner_ref: "f".repeat(32),
      }),
    ).toBe(false);
  });
  it.each([{}, { name: vpc.name }, { ...vpcBody, command: "apply" }])(
    "does not acknowledge a partial or augmented VPC intent %j",
    (body) => {
      expect(matchesNetworkIntent("vpcs", vpc, vpc.id, body)).toBe(false);
    },
  );
});
