# ADR 0003: Provider recovery and shared native TUN I/O

Status: accepted

The 2.0 Provider boundary must retain the 1.3.x connection-intent lifecycle.
`Disconnect` stops session traffic and restores owned network configuration while
keeping physical-network observation available. `Close` additionally releases the
observer. The multi-provider wrapper retains the active backend after a failed
attempt or disconnect, and disposes it before replacing the provider or shutting
down. Cleanup failure retains ownership and stops replacement. The daemon alone
schedules whole-VPN retries and filters network events against connection intent.

aTrust uses this same observer lifetime and processes all subsequent network
changes, including recovery after loss. Cancelling traffic precedes route/DNS
restoration, while the native device remains available until restoration completes.

`internal/tunio` owns the common TUN buffer contract: device-sized read batches,
16 bytes of native header headroom, validated segment sizes, and native write
error handling. Both AnyConnect and aTrust use it. It creates no device and changes
no system networking. aTrust's user-space stack relays UDP as datagrams, including
zero-length payloads, with bounded I/O deadlines.
