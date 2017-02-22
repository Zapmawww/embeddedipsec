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
2. If the packet protocol is AH or ESP, call `ipsec_lwip_input()` with that `netif`. Non-IPsec packets should not be passed to the adapter — continue the normal lwIP path for those.
3. The adapter fetches its own per-netif state from the lwIP client-data slot.
4. If the adapter returns `IPSEC_LWIP_ACTION_DELIVER`, replace the current `pbuf *p` with the returned decapsulated packet and continue normal `ip4_input()` processing. **Critical**: re-derive any local pointer to the IP header from the new pbuf immediately after replacement. In `ip4_input()` this means resetting the local `iphdr` variable (or equivalent) from `(struct ip_hdr *)p->payload` before inspecting `IPH_NEXTH` or any other field — the decapsulated inner IP header is now at the start of the new packet, and your previous pointer is stale.
5. If the adapter returns `IPSEC_LWIP_ACTION_DISCARD`, free the original packet and stop processing.

### IPv6 inbound

Hook in `ip6_input()` at the equivalent point: after basic IPv6 validation and before extension-header or upper-layer dispatch.

The action handling is the same as IPv4 inbound.

IPv6-specific note:

- Make sure the outer destination address is actually configured on the ingress netif in a usable state before you expect inbound AH or ESP traffic to reach the hook.
- If you assign a unicast IPv6 address with `netif_add_ip6_address()`, use the returned address-slot index and mark that slot `IP6_ADDR_PREFERRED`.
- If the configured address stays tentative or you mark the wrong slot, `ip6_input()` can drop the packet as "packet not for us" before IPsec sees it.

### IPv4 outbound

Hook in `ip4_output_if_src()` after lwIP has built the IPv4 header and before fragmentation/output is decided.

Why here:

- lwIP already knows the final source and destination addresses.
- lwIP can still do fragmentation after transport-mode protection.
- Tunnel-mode encapsulation can expand the packet before the existing fragmentation logic runs.

Call `ipsec_lwip_output_ipv4()` with the current `pbuf`, the selected `netif`, and the source and destination addresses.

Action handling:

1. `IPSEC_LWIP_ACTION_BYPASS`: keep the original `pbuf` and continue the existing lwIP path.
2. `IPSEC_LWIP_ACTION_DELIVER`: replace the packet in the current lwIP flow with the returned protected packet, recompute local header pointers, and continue the existing fragmentation/output path.
3. `IPSEC_LWIP_ACTION_DISCARD`: free the original packet and return `ERR_OK`.
4. `IPSEC_LWIP_ACTION_ERROR`: free the original packet and return an lwIP error such as `ERR_VAL` or `ERR_BUF`, depending on your local convention.

Ownership note:

- Do not read step 2 as "always free the original pbuf immediately".
- Free the original `pbuf` only if this hook point is the current owner-transfer point in lwIP, meaning the old packet will not continue through any later lwIP cleanup path.
- If your integration calls the adapter from a borrowed callback such as a `netif->output`-style hook, the original send-side `pbuf` still belongs to lwIP and must not be freed by the adapter caller.
- In that borrowed-hook case, either hand the replacement packet back through the surrounding call flow without touching the original ownership, or move the IPsec hook earlier to a place where packet replacement is explicit.

### IPv6 outbound

Hook in `ip6_output_if_src()` at the same stage: after the IPv6 header is present and before the packet is emitted.

Call `ipsec_lwip_output_ipv6()` with the selected `netif` and handle the returned action the same way as for IPv4.

## Multiple netif model

Do not share one adapter instance across all interfaces.

Use one adapter context per protected netif:

```c
struct my_ipsec_netif_ctx {
    ipsec_lwip_adapter adapter;
};
```

Each context should hold:

- One `ipsec_lwip_adapter` with its own fixed work buffer and attached `db_set_netif *`.
- Any tunnel endpoint metadata that your platform needs outside the core IPsec library.

Attach the adapter to the lwIP netif through lwIP's user client-data API. The adapter layer now allocates and caches its own client-data ID through `netif_alloc_client_data_id()`. The only public setup entry point is `ipsec_lwip_adapter_attach()`, which initializes the caller-owned adapter storage and binds it to the netif.

If you prefer one-step heap-managed setup for ports and tests, use `ipsec_lwip_adapter_attach_malloc()` and release it later with `ipsec_lwip_adapter_deinit()`.

## Manual lwIP changes to make

1. Set `LWIP_NUM_NETIF_CLIENT_DATA > 0` in `lwipopts.h`.
2. Allocate one `ipsec_lwip_adapter` and one `db_set_netif` per protected netif.
3. Call `ipsec_lwip_adapter_attach(netif, &adapter, databases)` when the netif is brought up, from lwIP core-locked context so `netif_alloc_client_data_id()` can run safely.
4. Reset inbound SA replay windows with `ipsec_sad_reset_replay()` whenever an inbound SA is installed or rekeyed.
5. Insert the inbound hook in `ip4_input()` and `ip6_input()`.
6. Insert the outbound hook in `ip4_output_if_src()` and `ip6_output_if_src()`.
7. After an outbound `DELIVER` action, continue through lwIP's existing fragmentation/output logic instead of sending the packet directly from the adapter.
8. Only free the original outbound `pbuf` if your chosen hook point truly replaces the packet in lwIP ownership terms. Do not free the original packet from borrowed send callbacks that lwIP will later clean up itself.
9. Keep reassembly in lwIP before inbound IPsec processing. Do not try to authenticate or decrypt IPv4 fragments independently.

## Test harness notes

The in-repo porting harness in `src/netif/porting-test.c` mirrors one practical integration pattern:

- It provisions one temporary protected netif per test case.
- It uses `tcpip_input()` for loopback reinjection so the normal lwIP ingress path runs on the tcpip thread.
- For IPv6, it adds the test address through `netif_add_ip6_address()` and marks the returned slot `IP6_ADDR_PREFERRED` before looped packets are injected.

That is test scaffolding, not a requirement for production ports, but it is a useful reference when your environment already runs the tcpip thread.

## Buffering model

The adapter uses a fixed-size contiguous work buffer because the core IPsec engine still performs in-place header insertion and removal.

That is a deliberate first step:

- It avoids chained-pbuf corner cases during the port.
- It keeps the core IPsec API unchanged.
- It is compatible with lwIP fragmentation and reassembly.
- It keeps memory ownership explicit: the port chooses whether adapter and database objects live in static storage, a board context, or some other caller-managed lifetime.

If you later want true scatter-gather or zero-copy operation, that will require a different core packet API, not just a thinner lwIP shim.
