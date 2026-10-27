import { describe, expect, it } from "vitest";
import { statusPresentation } from "../src/presentation";

describe("server state presentation", () => {
  const zh = (a: string, _b: string) => a;
  const en = (_a: string, b: string) => b;
  it("does not present acceptance, dispatch or uncertainty as completion", () => {
    for (const state of [
      "accepted",
      "sending",
      "dispatched",
      "uncertain",
      "unknown",
    ])
      expect(statusPresentation(state, zh).tone).not.toBe("good");
    expect(statusPresentation("succeeded", zh)).toEqual({
      label: "已完成",
      tone: "good",
    });
  });
  it("retains the existing instance and node labels in both languages", () => {
    expect(statusPresentation("running", zh)).toEqual({
      label: "运行中",
      tone: "good",
    });
    expect(statusPresentation("stopped", en)).toEqual({
      label: "Stopped",
      tone: "neutral",
    });
    expect(statusPresentation("maintenance", en)).toEqual({
      label: "Maintenance",
      tone: "warning",
    });
  });
  it("shows unrecognized server states without guessing success", () => {
    for (const state of ["new_state", "constructor", "__proto__", "toString"])
      expect(statusPresentation(state, zh)).toEqual({
        label: state,
        tone: "neutral",
      });
    expect(statusPresentation("", en)).toEqual({
      label: "Unknown",
      tone: "neutral",
    });
  });
});
