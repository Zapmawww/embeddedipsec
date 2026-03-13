# Modern lwIP Integration Guide

This repository still contains the old fake-netif adapter in `src/netif/ipsecdev.c`, but the modern porting path is to hook IPsec directly into lwIP's IP input and output paths.

## What changed in the core

- AH and ESP anti-replay state now lives on each `sad_entry` instead of in one global window per protocol.
- That makes separate SAs safe to use on different peers and on different netifs.
- The new `ipsec_sad_reset_replay()` helper gives the lwIP integration layer an explicit way to reset inbound replay state when an SA is installed or rekeyed.

## Adapter files in this repo

- `src/include/netif/ipsec_lwip_adapter.h`
- `src/netif/ipsec_lwip_adapter.c`

These files are intentionally not part of the default CMake build because lwIP is not vendored in this repository. They provide a modern adapter skeleton built around a fixed-size per-netif work buffer.

## Recommended hook points in lwIP 2.1.x

### IPv4 inbound

Hook in `ip4_input()` after the IPv4 header is validated and before the packet is dispatched by protocol.

Use the adapter like this:

1. Find the `ip_current_input_netif()` or the local `inp` netif.
2. Select that netif's IPsec adapter context.
3. If the packet protocol is AH or ESP, call `ipsec_lwip_input()`.
4. If the adapter returns `IPSEC_LWIP_ACTION_DELIVER`, replace the current `pbuf *p` with the returned decapsulated packet and continue normal `ip4_input()` processing.
5. If the adapter returns `IPSEC_LWIP_ACTION_DISCARD`, free the original packet and stop processing.
6. If the adapter returns `IPSEC_LWIP_ACTION_BYPASS`, continue the normal lwIP path unchanged.

### IPv6 inbound

Hook in `ip6_input()` at the equivalent point: after basic IPv6 validation and before extension-header or upper-layer dispatch.

The action handling is the same as IPv4 inbound.

### IPv4 outbound

Hook in `ip4_output_if_src()` after lwIP has built the IPv4 header and before fragmentation/output is decided.

Why here:

- lwIP already knows the final source and destination addresses.
- lwIP can still do fragmentation after transport-mode protection.
- Tunnel-mode encapsulation can expand the packet before the existing fragmentation logic runs.

Call `ipsec_lwip_output_ipv4()` with the current `pbuf`, source address, destination address, and the adapter context for the selected `netif`.

Action handling:

1. `IPSEC_LWIP_ACTION_BYPASS`: keep the original `pbuf` and continue the existing lwIP path.
2. `IPSEC_LWIP_ACTION_DELIVER`: free the original `pbuf`, replace it with the returned protected packet, recompute local header pointers, and continue the existing fragmentation/output path.
3. `IPSEC_LWIP_ACTION_DISCARD`: free the original packet and return `ERR_OK`.
4. `IPSEC_LWIP_ACTION_ERROR`: free the original packet and return an lwIP error such as `ERR_VAL` or `ERR_BUF`, depending on your local convention.

### IPv6 outbound

Hook in `ip6_output_if_src()` at the same stage: after the IPv6 header is present and before the packet is emitted.

Call `ipsec_lwip_output_ipv6()` and handle the returned action the same way as for IPv4.

## Multiple netif model

Do not share one adapter instance across all interfaces.

Use one adapter context per protected netif:

```c
struct my_ipsec_netif_ctx {
    ipsec_lwip_adapter adapter;
    db_set_netif *databases;
};
```

Each context should hold:

- One `db_set_netif *` for that interface.
- One `ipsec_lwip_adapter` with its own fixed work buffer.
- Any tunnel endpoint metadata that your platform needs outside the core IPsec library.

Attach the context to the lwIP netif by using lwIP client-data slots or your platform's netif wrapper. Do not use global adapter state.

## Manual lwIP changes to make

1. Add a per-netif IPsec context to your platform netif setup.
2. Allocate or assign one `db_set_netif` per protected netif.
3. Initialize the adapter with `ipsec_lwip_adapter_init()` when the netif is brought up.
4. Reset inbound SA replay windows with `ipsec_sad_reset_replay()` whenever an inbound SA is installed or rekeyed.
5. Insert the inbound hook in `ip4_input()` and `ip6_input()`.
6. Insert the outbound hook in `ip4_output_if_src()` and `ip6_output_if_src()`.
7. After an outbound `DELIVER` action, continue through lwIP's existing fragmentation/output logic instead of sending the packet directly from the adapter.
8. Keep reassembly in lwIP before inbound IPsec processing. Do not try to authenticate or decrypt IPv4 fragments independently.

## Buffering model

The adapter uses a fixed-size contiguous work buffer because the core IPsec engine still performs in-place header insertion and removal.

That is a deliberate first step:

- It avoids chained-pbuf corner cases during the port.
- It keeps the core IPsec API unchanged.
- It is compatible with lwIP fragmentation and reassembly.

If you later want true scatter-gather or zero-copy operation, that will require a different core packet API, not just a thinner lwIP shim.