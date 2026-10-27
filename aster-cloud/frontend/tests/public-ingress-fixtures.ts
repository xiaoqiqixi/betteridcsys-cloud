import type {
  PublicIngressPolicy,
  PublicIngressRule,
  PublicIngressOperation,
} from "../src/api/public-ingress";
export const ingressRule: PublicIngressRule = {
  id: "b".repeat(32),
  protocol: "tcp",
  source_cidr: "0.0.0.0/0",
  port_start: 443,
  port_end: 443,
};
export const ingressPolicy: PublicIngressPolicy = {
  schema: 1,
  instance_id: "2".repeat(32),
  owner_ref: "a".repeat(32),
  revision: 0,
  sha256: "c".repeat(64),
  rules: [],
  effective_revision: 0,
  state: "default",
  epoch_id: "",
  operation_id: "",
  bound_resource_id: "",
  legacy_unrestricted: false,
  updated_at: null,
  supported: true,
  unsupported_reason: "",
};
export const ingressRequest = { expected_revision: 0, rules: [ingressRule] };
export function ingressOperation(
  key = "d".repeat(32),
  actor = "a".repeat(32),
): PublicIngressOperation {
  const now = "2026-10-24T00:00:00Z";
  return {
    id: key,
    actor_id: actor,
    action: "public_ingress.update",
    target_instance_id: ingressPolicy.instance_id,
    request_sha256: "e".repeat(64),
    request: structuredClone(ingressRequest),
    result: {
      policy: {
        ...structuredClone(ingressPolicy),
        revision: 1,
        rules: structuredClone(ingressRequest.rules),
        effective_revision: 1,
        state: "active",
        operation_id: key,
        updated_at: now,
      },
    },
    created_at: now,
  };
}
