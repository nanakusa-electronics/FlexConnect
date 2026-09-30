# ADR: Linux daemon owns password persistence

Date: 2026-09-30

## Problem

The packaged Linux daemon runs as root before desktop login. The default Secret
Service backend depends on a session D-Bus and an unlocked default collection.
On the affected host it fails with "failed to unlock correct collection" and
systemd repeatedly restarts the daemon. The user's working desktop keyring does
not provide the root daemon's credential storage.

## Decision

Follow the daemon-owned storage boundary used by Tailscale: select the backend
before accessing secrets, independently of an interactive desktop session.
Linux defaults to the existing file backend; Windows/macOS retain keyring and
Docker retains its explicit memory backend. Environment overrides remain valid.
Explicit keyring mode continues to fail closed, with no error-driven fallback.

Passwords remain separate from profile metadata in `secrets.json` next to the
configured state file. The existing store restricts directories to 0700 and files
to 0600 and uses temporary files, atomic replacement, and fsync. The packaged
system daemon owns these files as root. This is plaintext storage, not TPM
sealing or application-level encryption. Disk encryption is a separate host
requirement. No API or state schema changes are needed.

## Compatibility and verification

Existing keyring users must explicitly select `FLEXCONNECT_SECRET_STORE=keyring`
to retain their backend, or enter passwords again after switching. No automatic
cross-user credential migration occurs. Profile secret references are preserved.
Regression tests cover default startup selection without an available keyring,
file persistence across store reconstruction, deletion, explicit keyring failures,
and existing file permission/atomic-write behavior.

References: [Tailscale daemon](https://tailscale.com/docs/reference/tailscaled),
[Tailscale store selection](https://github.com/tailscale/tailscale/blob/main/ipn/store/stores.go).
