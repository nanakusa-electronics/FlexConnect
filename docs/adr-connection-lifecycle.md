# Connection lifecycle and reconnect ownership

Status: proposed for review.

The previous daemon scheduled network repair separately from automatic reconnect. Each path
owned a teardown and replacement connection, while retry timers continued during sleep. The
underlay observer ended with the transport, so it could not report a later network recovery.

Tailscale keeps `WantRunning` separate from its current IPN state. `LocalBackend.linkChange`
updates network availability, and `controlclient.Auto.SetPaused` cancels in-flight work while
preserving the client's intent. FlexConnect uses this separation for its AnyConnect lifecycle,
while retaining the product's bounded three-attempt retry policy.

The daemon now owns one reconnect state containing the timer, attempt budget, generation and
cancel function. Physical-path repair, transient transport failure and system wake all request
work through this state. Backend operations remain serialized by the existing command mutex.
A new generation cancels the previous one; stale results and old connection events cannot
commit or tear down the replacement. Manual API commands cancel automatic work before waiting
for the mutex. Required-component cleanup failures still stop the daemon.

The protocol session retains its cleanup owner after transport close clears the active-session
pointer. Replacement waits for that owner's tunnel drain and propagates its cleanup error.
Pause cancels connection attempts while cleanup has its own bounded context. A drain timeout
is a cleanup failure, so a replacement cannot race unfinished workers or route teardown.

Connection intent is in memory and is established by a successful explicit connection. It
survives classified transient failures and retry exhaustion. After three attempts, there is no
further timer until a network change/recovery or Windows wake/unlock starts a new cycle. Manual
disconnect, selection of a different profile, shutdown and non-transient failures clear intent.
No state-schema migration or new persisted preference is introduced.

A connected session can be replaced once for a physical-path change even when auto-reconnect
is disabled; additional attempts require auto-reconnect (or machine mode). That first replacement
counts toward the same three-attempt budget. Suspend and underlay snapshot failure cancel and
pause attempts without spending the remaining budget. Windows lock alone does not mean suspend;
the service handles suspend and resume power events and uses unlock as a recovery signal.

The physical-network observer remains active after transport loss and manual teardown, is
refreshed with the next connection's TUN exclusion and identity, and closes on backend shutdown.
It emits a recovery event even when the interface, address and route return to identical values.
On Linux and macOS recovery is driven by physical-network notifications; explicit service power
events are currently Windows-specific. Existing `/v2` types and persisted state remain unchanged;
the reconnect snapshot now reports in-flight attempts as active and omits an absent retry deadline.

References (Tailscale revision `f5f326030b8b681079c84799ba5ec097601fcaff`):

- [LocalBackend intent and network availability](https://github.com/tailscale/tailscale/blob/f5f326030b8b681079c84799ba5ec097601fcaff/ipn/ipnlocal/local.go)
- [Control client pause/cancellation](https://github.com/tailscale/tailscale/blob/f5f326030b8b681079c84799ba5ec097601fcaff/control/controlclient/auto.go)
