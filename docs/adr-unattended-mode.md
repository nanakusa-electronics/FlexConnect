# Selected-profile unattended mode

Profiles and their create/update API payloads include `unattended_mode` (boolean,
default false). This additive field is persisted with the profile in schema 3.

After the local API starts, the daemon connects the current profile once when
this setting is enabled. The stored profile credentials and owner are used.
Machine profiles enter machine control mode through the existing control path.
The attempt has a two-minute deadline and is canceled during daemon shutdown.
Failures are logged; the local API remains available for recovery. Existing
connection lifecycle and reconnect rules continue to apply.

`flexconnectd --unattended_mode=true|false` overrides the profile setting for
that process. The existing environment-managed startup connection takes
precedence and suppresses this additional startup attempt.
