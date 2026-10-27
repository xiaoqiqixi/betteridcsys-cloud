import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { compileStyle, parse } from "@vue/compiler-sfc";
import { describe, expect, it } from "vitest";

const pages = resolve(import.meta.dirname, "../src/pages");
const directories = [
  ["NetworksPage", ".network-record"],
  ["OverlayNetworksPage", ".vpc-card"],
  ["PublicIPsPage", ".ip-record"],
  ["OperationsPage", ".operation-row"],
  ["AuditPage", ".audit-filters"],
  ["UsersPage", ".member-row"],
] as const;
const detailSurfaces = [
  ["components/OverlaySnapshotPanel.vue", ".snapshot-panel"],
  ["components/PublicIPResourcesPanel.vue", ".vm-public-resource"],
  ["components/InstanceMetricsPanel.vue", ".metrics-panel"],
  ["components/InstanceObservationPanel.vue", ".observation-panel"],
  ["components/SourceRetirementPanel.vue", ".retirement-panel"],
  ["components/PublicIngressPanel.vue", ".public-ingress-panel"],
  ["components/OperationRecord.vue", ".task-record"],
  ["pages/OverlayEpochPage.vue", ".node-task"],
  ["pages/InstanceDetailPage.vue", ".artifact-list"],
] as const;

describe("continuous directory presentation contracts", () => {
  for (const [name, selector] of directories) {
    it(`${name} compiles its scoped desktop/mobile ledger rules`, () => {
      const source = readFileSync(resolve(pages, name + ".vue"), "utf8");
      const { descriptor, errors } = parse(source);
      expect(errors).toEqual([]);
      const style = descriptor.styles.find((entry) => entry.scoped)!;
      const result = compileStyle({
        filename: name + ".vue",
        source: style.content,
        id: "data-v-directory-contract",
        scoped: true,
      });
      expect(result.errors).toEqual([]);
      expect(result.code).toContain(selector);
      expect(style.content).toContain("var(--border)");
      expect(style.content).not.toMatch(/border-radius:\s*(?:14|16)px/);
    });
  }

  it("keeps IPAM and VPC object directories continuous rather than two-column tiles", () => {
    for (const [name, selector] of [
      ["NetworksPage", "network-records"],
      ["OverlayNetworksPage", "vpc-list"],
      ["PublicIPsPage", "ip-records"],
    ]) {
      const source = readFileSync(resolve(pages, name + ".vue"), "utf8");
      const block = source.match(
        new RegExp(`\\.${selector}\\s*\\{([^}]+)\\}`),
      )?.[1];
      expect(block).toContain("display: block");
      expect(block).not.toContain("grid-template-columns");
    }
  });

  for (const [relative, selector] of detailSurfaces)
    it(`${relative} keeps scoped detail presentation compilable without large rounded cards`, () => {
      const filename = resolve(pages, "..", relative);
      const source = readFileSync(filename, "utf8");
      const { descriptor, errors } = parse(source);
      expect(errors).toEqual([]);
      const style = descriptor.styles.find((entry) => entry.scoped)!;
      expect(
        compileStyle({
          filename,
          source: style.content,
          id: "data-v-detail-surface",
          scoped: true,
        }).errors,
      ).toEqual([]);
      expect(style.content).toContain(selector);
      expect(style.content).not.toMatch(/border-radius:\s*(?:12|14|16)px/);
    });

  it("presents snapshot routing and NAT as one continuous relationship workspace", () => {
    const source = readFileSync(
      resolve(pages, "../components/OverlaySnapshotPanel.vue"),
      "utf8",
    );
    const panel = source.match(/\.snapshot-panel\s*\{([^}]+)\}/)?.[1];
    expect(panel).toContain("grid-template-columns: minmax(0, 1fr)");
    expect(panel).not.toContain("1fr 1fr");
  });
});
