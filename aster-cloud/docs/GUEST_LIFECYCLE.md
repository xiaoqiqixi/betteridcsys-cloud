# Guest lifecycle

Enable `guest.enabled` in the root-owned node configuration after installing
`libguestfs-tools`, `openssl` and `cloud-image-utils`; `--doctor` verifies them.
Map approved image IDs to `linux`/`windows` in `guest.families`, and explicitly
list approved Linux rescue IDs in `guest.rescue_images`. Rescue attaches the
original disk read-only unless root sets `guest.rescue_writable: true`.

Lifecycle mutations upgrade the node journal to schema 7. Older binaries
refuse it. Rollback of a binary requires an operator-reviewed state migration;
never edit the schema number to bypass this guard. Reconciliation never repeats
an action or deletes a recovery disk. An interrupted action remains uncertain.

Reinstall verifies the approved image digest and size, observes stopped state,
renames the original disk and seed files with `.before-<operation>`, creates a
new overlay and cloud-init instance identity, then defines and starts it. The
original disk is removed only after running is observed and checkpointed. A
failure can restore the original only while stopped state and one of the two
owned definitions are proven. Otherwise both disks remain for operator review.
Rescue state (operation, image, digest and attachment mode) survives restart.

Suspend persists the start block before forced shutdown. Unsuspend clears it;
`start_after` is the only request to boot. Resize requires an already stopped
instance, checks the node allocation budget, permits CPU/memory decreases and
system disk growth, and leaves the instance stopped. Cloud-init growpart handles
partition growth at the next boot on supported images. OVS uses its existing
fenced power path for suspend/unsuspend; disk lifecycle capability is not
advertised for OVS. Snapshots remain stopped-only on normal networks and are
refused during rescue or recovery.

Password reset uses the offline libguestfs `virt-customize --root-password`
file selector with an inherited stdin pipe, `--no-network` and `--no-logfile`.
Windows and images without an explicit Linux family return `UNSUPPORTED_GUEST`.
Reinstall hashes a password through `openssl passwd -6 -stdin` before writing
cloud-init user-data. Plaintext credentials never reach argv, environment,
controller/node records, audit, diagnostics or host seed files. The guest's
password hash is intentionally present in its cloud-init seed and shadow file.

Sources: [libguestfs options](https://libguestfs.org/virt-customize.1.html),
[cloud-init users and growpart](https://docs.cloud-init.io/en/latest/reference/modules.html),
[OpenSSL password hashing](https://docs.openssl.org/4.1/man1/openssl-passwd/).
