# ADR 0002: Explicit aTrust deployment compatibility

Status: accepted for local development

## Context

Hostname-selected fallbacks coupled the reusable GeekTrust client to one school.
The same configuration must reach the CLI, daemon and library, and disabling an
option must also work when restoring a saved session.

## Decision

Add `atrust_compatibility` to Profile and the v3 create/update contracts. Reuse
GeekTrust's public `deployment.Compatibility` data type and validator. This is
non-secret protocol configuration; credential references remain separate.
Defaults are empty/false for every controller. An update replaces the complete
object; `{}` resets it. Unknown fields fail decoding. No migration or automatic
hostname presets are provided.

The CLI imports a bounded JSON file through the existing local API. The daemon
persists a copy in schema 3 and passes it to the aTrust backend. Active profile
changes use the existing disconnect, network cleanup and reconnect transaction.
Network ownership and authentication-secret storage do not change.

Explicit settings cover application and missing-gateway fallbacks, missing
node-group fallback, TLS server name, TCP-to-L3 fallback and process metadata.
They cannot override a nonempty server-assigned node group or an explicit
transport authorization denial. The SDK copies settings per client and restores
routing from current policy/configuration rather than old persisted addresses.

## Consequences

Future deployments add documented, typed protocol settings when needed, without
a dynamic plugin registry or a school-name switch. Remove a setting when the
associated protocol behavior is no longer supported; defaults never change based
on hostname. Test enabled, disabled, reload and rejection paths for each setting.
Library capability diagnostics describe implementation separately from resource
policy and established transport state. Release still requires a published
GeekTrust module version; the development Go workspace is not a release dependency.
