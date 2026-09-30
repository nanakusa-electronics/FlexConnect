# FlexConnect 1.3 Architecture

## Control plane

`flexconnectd` is the only process allowed to own VPN, TUN, route, DNS, or SOCKS5 state. The CLI
and tray use the typed client in `client/local` over a Unix socket or Windows named pipe. The local
HTTP surface is API major 2 only; API v1 and the browser console are intentionally absent.

`GET /v2/live` proves only that the process and HTTP handler are alive. `GET /v2/ready` reports the
component registry and returns 503 while a required component cannot accept new operations. Every
error response uses a stable code, sanitized message, request ID, and retryable flag.

Windows derives the actor SID, LocalSystem identity, and elevation state from the named-pipe client
token. User profiles are owned by that SID. LocalSystem bypasses user isolation; elevated
administrators can manage machine profiles and control mode. In machine mode ordinary users have
read-only, redacted status and cannot change or stop the connection.

## State and operations

State schema 2 stores profiles, per-SID selections, control mode, and durable profile/secret intent.
There is no schema migration from the pre-1.3 format. Missing ownership or scope is a startup error,
and the old file is not modified.

Profile and secret mutation follows a persisted intent transaction: validate, write intent, create
the new secret, atomically replace state, remove the old secret, then clear intent. State, secret,
and network journals use same-directory random temporary files, file and directory synchronization,
atomic replacement, and restrictive platform permissions.

Mutations involving a live connection return an operation. The profile update itself is committed
before the asynchronous disconnect/reconnect begins. Running operations can be queried; terminal
operations are published to the watch ring and immediately removed from the operation map.

## Connection ownership

Each attempt has a random attempt ID, connection ID, profile ID, owner ID, and cancel context.
Blocking backend work does not hold the backend publication mutex. Only the current attempt may
commit a result. Disconnect, switch, active update, delete, repair, shutdown, and API operations are
serialized at the supervisor boundary, and stale backend events are rejected by connection identity.

Connected is published only after CSTP/TLS, offered DTLS, TUN, route, DNS, underlay monitoring, and
an enabled SOCKS5 listener are ready. A switch failure retains the new selected profile and enters
Error. Automatic reconnect retries only classified transient network, DNS, timeout, and underlay
failures, with exponential backoff and a maximum of 3 attempts. Machine mode forces that policy and
remains locked after failure or exhaustion.

Connection intent survives a transient transport loss independently of the connected session.
One daemon lifecycle owns both physical-path replacement and reconnect backoff; its generation
and cancel context invalidate obsolete transactions before another can run. Suspend or an
unavailable physical path pauses attempts. Network recovery (including return to the same path),
path changes, or Windows resume/unlock can start a fresh bounded retry cycle after exhaustion.
Manual disconnect and non-transient failures clear intent. Network observers survive transport
loss and are closed with the backend. See [the lifecycle decision](adr-connection-lifecycle.md).

## Network transaction

The network manager persists `network-ownership.json` before applying static or dynamic route/DNS
state. Cleanup removes only exact objects owned by the connection. If cleanup fails, the journal is
retained, writes are rejected, readiness fails, and the daemon exits non-zero. The next elevated
startup restores the journal before constructing the service or opening the API.

Linux uses netlink route add/delete plus systemd-resolved D-Bus, NetworkManager D-Bus, or resolvconf;
it never overwrites `/etc/resolv.conf`. macOS uses direct route commands and a fixed SystemConfiguration
dynamic-store key through structured `scutil` stdin. Windows serializes winipcfg state and records
physical route ownership; Wintun-owned address and DNS state disappears with the adapter handle.

Dynamic split routes are reconciled by one worker. DNS names are canonicalized and matched on label
boundaries, IPv4 answers and CNAME ownership are validated, TTL is clamped to 30 seconds through one
hour, shared addresses remain until their last lease expires, and the set is capped at 4096 unique
addresses. A limit or reconciliation error is visible in health, diagnostics, and watch while the
existing VPN remains intact.

## Verification boundary

CI runs unit/integration tests, race-sensitive packages, vet, native builds on Windows/Linux/macOS,
Windows named-pipe identity integration, a Linux network-namespace route transaction, DNS/scutil
contracts, platform packaging, and a Docker build. These are automated engineering checks, not
evidence of a real AnyConnect deployment, real end-user platform networking, or an independent
security scan.

## TUN packet I/O verification

Native TUN writes follow Tailscale's injection boundary: reserve 16 bytes before
IP packet data and determine write success from the returned error. The pinned
wireguard-go Linux implementation returns bytes (including a virtio header when
active), while Windows/macOS return packet counts. Reads use `BatchSize()` and
forward every returned segment into independently owned transport payloads.
User-space netstack devices have a separate zero-offset, single-packet contract.

CI and release validation exercise real Linux TUN packet I/O in an isolated
network namespace, in addition to fake device and race tests. To run locally
without changing host routes, compile as the ordinary user and execute in a
new user/network namespace:

```bash
GOTOOLCHAIN=go1.26.2 go test -c -o /tmp/flexconnect-tun.test ./internal/anyconnect/tunnel
unshare -Urn env FLEXCONNECT_TUN_TEST=1 /tmp/flexconnect-tun.test -test.run '^TestNativeLinuxTUNPacketIO$' -test.timeout=15s
```

Hosts disabling user namespaces require an administrator to run the test with
`sudo unshare --net` instead. The test is opt-in and does not authenticate to a
VPN server. Passing it proves native packet handling, not end-to-end AnyConnect
compatibility with a particular server.
