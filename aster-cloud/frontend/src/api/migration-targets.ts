import { record } from "./client";
import { clusterID } from "./overlay";
export interface MigrationTargets {
  complete: true;
  items: { node_id: string; eligible: boolean; reason: string }[];
}
export function validMigrationTargets(v: unknown): v is MigrationTargets {
  return (
    record(v) &&
    v.complete === true &&
    Array.isArray(v.items) &&
    v.items.length <= 4096 &&
    v.items.every(
      (t) =>
        record(t) &&
        clusterID(t.node_id) &&
        typeof t.eligible === "boolean" &&
        typeof t.reason === "string" &&
        /^[A-Z0-9_]{0,80}$/.test(t.reason),
    ) &&
    new Set(v.items.map((t) => t.node_id)).size === v.items.length
  );
}
