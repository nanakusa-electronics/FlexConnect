# ADR 0001: Explicit VPN providers and network ownership

Status: Accepted for FlexConnect 2.0 development.

The local API is `/v3` and persisted state is schema 3. Profiles explicitly
select a provider and authentication method. Older API paths and state schemas
are rejected, and old state files are not overwritten. The CLI and tray use the
same typed local client and continue to select one active profile.

The daemon alone owns system TUN, routes, DNS, proxy listener, connection
lifecycle, and the network recovery journal. Provider sessions expose protocol
data and events. AnyConnect retains its packet path; aTrust uses GeekTrust as a
linked library for authentication, policy, DNS resolution, TCP/UDP, and optional
ICMP packet transport. A provider switch must restore the previous session's
network objects before opening the replacement. Failed cleanup halts switching.

Passkey keystores enter through local IPC and are kept by the daemon's secret
store. Large payloads are encrypted in private files using a key protected by
the configured secret store. The source file remains the user's responsibility;
concurrent use can corrupt the authenticator counter. Gateway public-key pins
and the aTrust device identity are scoped to the stable profile ID, so rotating
the credential does not silently reset first-use trust or device registration.
A changed gateway pin terminates connection.

The GeekTrust module is developed locally in a Go workspace. Release builds
must pin a published GeekTrust version and remove the workspace dependency.
Public contribution and distribution remain subject to upstream authorization.
