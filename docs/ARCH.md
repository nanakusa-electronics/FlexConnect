# FlexConnect 2.0 Architecture

## Control plane

`flexconnectd` is the only process allowed to own VPN, TUN, route, DNS, or SOCKS5 state. The CLI
and tray use the typed client in `client/local` over a Unix socket or Windows named pipe. The local
HTTP surface is API major 3 only; older API versions and the browser console are absent.

`GET /v3/live` proves only that the process and HTTP handler are alive. `GET /v3/ready` reports the
component registry and returns 503 while a required component cannot accept new operations. Every
error response uses a stable code, sanitized message, request ID, and retryable flag.

Windows derives the actor SID, LocalSystem identity, and elevation state from the named-pipe client
token. User profiles are owned by that SID. LocalSystem bypasses user isolation; elevated
administrators can manage machine profiles and control mode. In machine mode ordinary users have
read-only, redacted status and cannot change or stop the connection.

## State and operations

State schema 3 stores profiles, per-SID selections, control mode, and durable profile/secret intent.
There is no state migration. Missing ownership, scope, provider, or authentication method is a startup error,
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

Connected is published only after provider authentication, an authorized gateway, TUN, route, DNS, underlay monitoring, and
an enabled SOCKS5 listener are ready. A switch failure retains the new selected profile and enters
Error. Automatic reconnect retries only classified transient network, DNS, timeout, and underlay
failures, with exponential backoff and a maximum of 3 attempts. Machine mode forces that policy and
remains locked after failure or exhaustion.


Each profile explicitly selects `anyconnect/password` or `atrust/ecnu_passkey` or
`atrust/shanghaitech_passkey`. The daemon switches through one backend factory and one
active session. aTrust authentication, resource policy, TCP/UDP, and optional packet
transport live in GeekTrust; FlexConnect owns the OS TUN, route, DNS, and SOCKS5 listener.
Before switching providers, the daemon closes the old session and restores its network
objects. A cleanup failure stops the switch. Connection IDs reject late events.
