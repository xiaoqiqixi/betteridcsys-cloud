# Billing service API

`contracts/billing/serviceapi` is the shared `aster.service/1` SDK. It uses the
same fixed DNS/CIDR, verified TLS, no-proxy, no-redirect, single-dial transport as
the provisioning SDK. Every call requires the billing token and
`X-Aster-Owner-Ref`; an owner mismatch returns 404. Browser Origin headers are
rejected. Read tokens and administrator tokens cannot use this API.

Add the approved catalog to the existing root-owned controller configuration:

```json
"service": {
  "snapshot_limit": 3,
  "images": [{
    "id": "ubuntu22", "family": "linux", "name": "Ubuntu",
    "version": "22.04", "min_disk_gb": 4,
    "sha256": "<approved image SHA-256>", "node_ids": ["node-one"]
  }]
}
```

Set `rescue: true` on approved rescue entries. The corresponding node image ID,
SHA-256, family and rescue approval must match. Catalog writes are operator
configuration changes; the API never accepts an image path, source URL or XML.
Zero snapshot quota disables the billing snapshot capability. Snapshots use the
existing stopped-only normal-network storage operations.

Action requests bind `Idempotency-Key` to `operation_id` and
`X-Aster-Request-SHA256` to the SDK's canonical request digest. The first result
is a durable accepted/rejected receipt. A matching replay returns that same
receipt with HTTP 409, even after the underlying operation changes state. A
different digest under the same ID is a conflict. Progress comes only from the
read-only action resource. Uncertain actions are never automatically retried.
The service power field includes durable starting, stopping, rebooting and
reinstalling intents. An uncertain operation reports unknown power without
dispatching or reconciling work from the read endpoint.

The controller persists a redacted node task and password commitment. The live
password goes once in an ephemeral node mTLS header, bound to that operation.
Neither controller nor node stores the password. A lost password or unavailable
in-memory dispatcher quarantines the intent; recovery cannot reconstruct or
resubmit credentials. Supply a new explicit operation only after resolving the
uncertain operation through the operator workflow.

Capabilities are the intersection of configured policy, fresh pinned-node
capabilities and the instance's network and image. OVS instances do not expose
disk lifecycle or snapshots. Missing metrics storage yields an empty series and
`metrics: false`; it never fabricates measurements. Console capability requires
the console ticket service. See [guest lifecycle](GUEST_LIFECYCLE.md) for node
configuration and disk recovery rules.
