import { publicIdentityIntent, type IdentityAction } from "../src/api/identity";
import { admin } from "./fixtures";
export function identityFixtureResponse(
  action: IdentityAction,
  key: string,
  body: unknown,
  target = { ...admin, id: "e".repeat(32), email: "target@example.invalid" },
) {
  const intent = publicIdentityIntent(body)!;
  return {
    user: {
      ...target,
      name: intent.name ?? target.name,
      email: intent.email ?? target.email,
      role: intent.role ?? target.role,
      permissions: intent.permissions ?? target.permissions,
      enabled: intent.enabled ?? target.enabled,
      revision: intent.revision + 1,
    },
    operation: {
      id: key,
      actor_id: admin.id,
      target_id: target.id,
      action,
      base_revision: intent.revision,
      result_revision: intent.revision + 1,
      intent,
      request_sha256: "d".repeat(64),
      reason: intent.reason,
      audit_id: "123",
      completed_at: "2026-10-26T10:00:00Z",
    },
  };
}
