# Console identity integration

This package authenticates **controller staff**, not financial customers. Console
user IDs are never assumed to equal billing `owner_ref`; there is no shared login
or implicit tenant binding. `viewer` can read controller infrastructure but cannot
mutate it. Tenant self-service needs a separate, explicit ownership mapping.

Construct `New(db, Config{Origin: "https://fixed-console-origin"})` after applying
the complete current controller migrations (identity tables from `002`, members index from `011`, revisions/operations from `012`). Mount `Handler()` for the identity endpoints and use
`Require(permission, handler)` for every other console endpoint. Read `Actor(ctx)`
inside the handler and enforce operation-specific ownership and dangerous/restore
permissions there too. This middleware is not a substitute for those checks.

Only real TLS requests are accepted; `X-Forwarded-*` is not trusted. Behind a proxy,
use a separately authenticated TLS upstream rather than bypassing this check.
All mutations, including login, require the exact configured `Origin` and
`X-CSRF-Token`. No cross-origin CORS is enabled. Only `GET /console/v1/users` accepts the bounded `cursor` query documented below; all other identity endpoints still reject queries. Resource GET handlers wrapped by `Require` may validate their own pagination/filter queries. Unsafe methods reject queries. Bodies require JSON, reject unknown/duplicate top-level keys,
and are capped at 16 KiB.

Login flow: `GET /console/v1/auth/csrf`, retain the Secure/HttpOnly/SameSite=Lax
`__Host-aster-cloud-session` cookie, then `POST /console/v1/auth/login` with the
returned CSRF token. Login rotates and invalidates the previous token. `auth/me`
returns the live user and same session-bound CSRF token. Sessions have a fixed
absolute lifetime (default eight hours; maximum 24); anonymous login sessions
expire in ten minutes. Session tokens are random 256-bit values and only their
SHA-256 hashes persist. CSRF tokens are domain-separated HMACs of the secret
cookie token. Changing password, email, grants or enabled state revokes all user
sessions; current grants/enabled status are also fetched on each request.

Passwords must be 12–1024 bytes. Hashing uses random 128-bit salts and PBKDF2-SHA256
with 600,000 iterations and 256-bit outputs. Unknown accounts run the same KDF.
Persistent 15-minute attempt limits are ten per normalized email and forty per
direct peer IP (no untrusted forwarding headers); successful attempts also count.
Fresh anonymous sessions are additionally capped at forty per normalized direct
peer and 4096 globally per fifteen minutes, with no more than 4096 live anonymous
sessions. Existing valid cookies reuse their session and do not consume this
creation budget. Invalid peer addresses fail closed. Creation cleans at most 100
expired sessions and 100 limit buckets older than 24 hours; valid sessions are
never removed by cleanup. Fresh-session throttling returns 429 `RATE_LIMITED`.
Login failures do not distinguish unknown, disabled or incorrect credentials.
`Retry-After: 900` accompanies 429. These bounded limits do not replace network
DoS controls, MFA or account recovery, which are not implemented here.

`Bootstrap(ctx,email,name,passwordBytes)` creates the initial admin only if the
user table is empty, serialized with all identity changes. CLI callers must read
the password from private stdin/terminal, never flags/environment/logs, and clear
their input buffer. There is no seeded/default password. The singleton DB lock
protects last-enabled-admin invariants and concurrent changes. A user cannot
change their own role/grants or disable themselves. `admin` can administer all
accounts. `users.manage` on any non-admin role is **bounded delegation**, not an
implicit administrator grant: both an existing target's grants and the proposed
grants must be subsets of the manager's own current grants. Non-admin managers
cannot create, reset credentials for, or otherwise edit any `admin` account, even
if a custom manager separately holds every permission. Role grants are fixed server-side except `custom`,
whose explicit grants must all belong to the published whitelist. Operator does
not implicitly gain dangerous instance actions, restores, migrations, account or
node configuration rights. Roles are included by `GET /console/v1/roles`.

Identity audit records are append-only through this package and contain actor,
target, action and UTC time, never password/session/CSRF material. Credential
failures use a SHA-256 email target rather than raw supplied text. External log
retention/export, MFA, self-service password recovery, identity-provider
federation and tenant accounts are separate work, not claimed complete here.

## Tests

Unit tests always run. Real MySQL tests explicitly skip if both fixture variables
are absent. Prefer `ASTER_CLOUD_TEST_DSN` whose database name **must contain
`_test`**, or the existing native CI `ASTER_MYSQL_TEST_DSN` whose database must be
exactly `aster_ci_test`. In either case the fixture principal needs CREATE/DROP
DATABASE on the isolated test server: the test creates a random
`aster_cloud_test_identity_<hex>` database, applies identity migrations 002, 011 and 012, and drops
that database on cleanup. It never reuses customer/controller tables or prints
DSNs. Do not provide any production DSN. A skipped local test is not MySQL
acceptance; CI must run with the real fixture and zero skips.

## Complete members pagination (W07-A, schema 11)

`GET /console/v1/users` requires the same current `users.manage` permission as before. Its optional single `cursor` is an untrusted seek position, not a signed-in identity or a grant; changing it never bypasses the current session, enabled state, or permissions. All existing create/update/delegation and last-administrator contracts remain unchanged.

Response: `{items,limit:100,next_cursor:string|null,truncated_possible:boolean}`. The compatibility boolean now means **an actual 101st row exists**, not a fixed truncation warning. A page may contain 0–100 users; a non-null next cursor requires exactly 100 returned users. There is no total count, offset, search, role filter, or arbitrary page jump in this slice.

Rows are ordered by `created_at ASC,id ASC`. `LIMIT 101` supplies only the has-more lookahead; next position is the **100th returned** row, not the lookahead row. The UTC microsecond timestamp and ID preserve ties without client-side time conversion. Static traversal does not duplicate or omit rows. This is not a long-running snapshot across concurrent account creation, rename, or disable operations; returning to an earlier page reloads current data.

Only `?cursor=u1.<canonical-unpadded-base64url>` is supported. Its exact compact JSON is `{"at":"2026-10-25T00:00:00.123456Z","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` with fixed field order, six UTC fractional digits and 32 lowercase hexadecimal ID bytes. Values are bounded to 512 characters, the query to 600 bytes; duplicate/unknown keys, empty cursor/query, wrong version, noncanonical encoding, aliases, extra/duplicate JSON fields, nulls and invalid MySQL-range UTC times return `400 INVALID_QUERY`. The position is passed as parameterized SQL values. Other identity queries and every write query remain rejected.

The console uses previous/next navigation with an in-memory, identity-bound page stack. Page/count advance only after a validated response; a failed next request retries that intended page. A 401/403 clears rows and cursors; identity/permission changes close the old editor and discard late responses. No account writes occur while navigating. The new frontend deliberately refuses legacy responses without `next_cursor`, rather than calling their truncated list complete; deploy matching frontend/backend assets.

Index migration, rollback and acceptance boundaries: [members pagination](../../docs/MEMBERS_PAGINATION.md).

## Queued identity writes and session revocation (W07-B1)

Create/update require an internal request proof containing only the authenticated
session hash and user ID. `Require` supplies it after live authentication and CSRF;
an actor ID alone is not sufficient, even for the unexported Store entry points.
No proof or bearer cookie is added to the public User DTO or persisted tasks.

The write transaction locks `identity_lock`, then uses a locking current read of
that exact session. Missing, anonymous, mismatched or expired sessions return
`401 AUTH_REQUIRED`; expiry is evaluated after row-lock waits. Session storage
errors remain unavailable (503), never success or a fabricated rejection. The
session lock is held through commit. Logout uses the same identity→session order;
original current-grant/delegation/self-protection/last-admin checks and atomic
audit behavior remain in force. Another valid device session is unaffected by
ordinary single-session logout.

HTTP regressions pause at the first request-body read, after actual authentication,
and commit logout/password reset or advance the private clock before releasing
the request. They require a complete JSON 401 and no account/audit write. Store
tests seed and remove actual private DB sessions, without any production bypass.
This does not claim revision conflict handling, explicit all-session revocation,
MFA/SSO, or a fence for already accepted resource operations. Full design and
remaining identity contracts: repository `docs/IDENTITY_SESSION_FENCE.md`.


## Account revisions and identity receipts (W07-B, schema12)

Create/update and explicit all-session revocation require one stable lowercase
32-hex Idempotency-Key and a single-line reason (1–500 Unicode code points).
Update/revoke also require the latest revision; a stale revision returns409
REVISION_CONFLICT, never an overwrite. Used keys return409 OPERATION_USED; no
credential request is replayed. Every committed user change, session deletion,
audit and operation receipt is one transaction. Ordinary name changes do not
revoke existing device sessions. Revocation fences already-started login issuance
by rechecking both revision and password hash under the identity lock.

Mount the current Console.Handler dispatcher, including
`GET /console/v1/identity-operations/{key}`. Only its originating current manager
may read a receipt, and target delegation is checked again. A404/current profile
is not proof that an unknown write did not execute. Passwords and password hashes
are absent from receipts; the public intent records only password_changed.

The Vue ledger preserves full non-secret intents before sending, locks the same
actor/target across changed drafts, and reconciles only the original receipt.
Self-revocation exits authenticated UI even after a lost response; a fresh login
can verify its own retained record. Frontend/backend must deploy together; old
clients missing key/revision/reason are rejected. Rollback requires a matching
schema backup. Application receipts have no update/delete API; the current
schema-level runtime DML grant is NOT database-enforced append-only permission.
See [the complete contract](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/IDENTITY_OPERATIONS.md).
