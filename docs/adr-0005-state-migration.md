# ADR 0005: Migrate 1.3.x state on daemon startup

Status: Accepted. Supersedes ADR 0001's rejection of schema 2.

FlexConnect 1.3.x uses schema 2 at the same state location as 2.0. Rejecting
that state prevents the Windows service from starting during an MSI upgrade.
The daemon now upgrades schema 2 to schema 3 during initialization on all
platforms. All existing profiles and pending transaction profiles receive
provider `anyconnect` and authentication method `password`.

Profile identifiers, ownership, selections, control mode, routes, DNS and
secret references remain intact. Migration does not move or rewrite passwords
or change the configured secret backend. Profile validation and pending
transaction recovery run before initialization succeeds. The existing atomic
state writer persists schema 3 before the local API becomes available. Invalid
state and unsupported schema versions remain errors; failed writes prevent
startup. Subsequent starts use schema 3 without another migration.

Migration is one-way. Returning to 1.3.x requires restoring a pre-upgrade state
backup. The local API remains v3, and old CLI/tray binaries must be upgraded.
