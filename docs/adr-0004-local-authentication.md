# ADR 0004: Daemon-owned authentication challenges

Status: accepted for 2.0 development.

The aTrust controller may require an SMS code after Passkey authentication. The
library exposes a cancellable callback; the daemon owns user interaction, following
the existing local API and watch model used by connection operations.

A provider callback creates one in-memory challenge bound to the connection and
attempt. Its deadline is the earliest of the provider deadline, caller deadline,
and one minute. Only SMS is currently supported. Unknown methods fail without an
automatic authentication retry. Canceling the connection or stopping the daemon
ends the wait.

`GET /v3/authentication` returns the current accessible challenge or `null`.
`POST /v3/authentication/{id}` accepts `{"response":"123456"}` once and returns
204 when queued. The provider still decides whether authentication succeeds.
Only the profile owner or an administrator can access its challenge, subject to
the daemon's existing control-mode rules. Missing, completed and expired requests
return `authentication_not_found`. Responses are numeric, limited to 32 characters,
and never persisted, returned in events, or included in errors.

Watch snapshots include pending challenge metadata. Replay filters out completed
or inaccessible challenges. The tray deduplicates prompts by challenge ID and
instructs the user to run `flexconnect auth respond`. The CLI reads a masked code,
or accepts `--response-stdin`; it never accepts codes as positional arguments.
Human input is collected outside ordinary HTTP timeouts, and the daemon rejects
answers after expiry. No browser, callback listener, or new storage layer is used.
