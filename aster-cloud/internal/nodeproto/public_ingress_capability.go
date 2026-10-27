package nodeproto

// PublicIngressCapability identifies binaries that enforce the explicit,
// instance-bound public ingress policy carried by floating IP snapshots.
// Legacy overlay/1 support alone does not authorize this contract.
const PublicIngressCapability = "floating-public-ingress/1"
