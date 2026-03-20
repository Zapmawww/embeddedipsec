# Using IPsec From an Application

This guide explains how an application should use embedded IPsec when the network stack is lwIP and the application sends traffic through the normal socket API.

The important model is:

- The application does not enable IPsec by calling a socket-level `setsockopt()` API.
- Instead, a control/configuration layer provisions Security Associations (SAs) and Security Policy Database (SPD) entries for a netif.
- After that, the application keeps using normal sockets such as `socket()`, `bind()`, `send()`, `sendto()`, `recv()`, and `recvfrom()`.
- The lwIP hook layer decides whether each packet is bypassed, discarded, or protected with AH/ESP based on the SPD entry that matches the packet.
- Outbound policy lookup is first-match-wins, so rule order is part of the design, not an implementation detail.

## What this library does and does not provide

This repository currently provides a packet-transform engine plus SA/SPD management.

It does provide:

- Manual-keyed AH and ESP processing.
- IPv4 and IPv6 policy matching.
- Tunnel mode and transport mode.
- A direct-hook lwIP adapter in [src/include/netif/ipsec_lwip_adapter.h](src/include/netif/ipsec_lwip_adapter.h) and [src/netif/ipsec_lwip_adapter.c](src/netif/ipsec_lwip_adapter.c).

It does not provide:

- IKE or automatic key management.
- Kernel-style socket options such as Linux XFRM or BSD IPsec `setsockopt()` APIs.
- A per-socket IPsec control API.

Because of that, IPsec configuration must happen in application code, system startup code, or a dedicated control task that owns the SA/SPD state.

## High-level integration model

For each protected lwIP netif you need:

1. Either one caller-owned `ipsec_lwip_adapter` plus one caller-owned `db_set_netif`, or a single call to `ipsec_lwip_adapter_attach_malloc()`.
2. Backing storage for inbound and outbound SAD/SPD tables, either caller-owned or heap-allocated by the helper.
3. One-time attachment of the adapter to the netif.
4. SPD entries that describe which socket traffic should be protected.
5. Matching inbound and outbound SA entries carrying the SPI, mode, algorithms, and keys.

Once this is configured, socket traffic is ordinary lwIP traffic. The IPsec layer sits below the sockets API, not inside it.

## How application policy maps to sockets

Since there is no per-socket IPsec API, the application expresses intent indirectly through SPD entries.

In practice:

- If you want to protect a TCP client connection to `192.168.1.20:4321` from local port `1234`, create an SPD entry that matches source address, destination address, protocol `IPSEC_PROTO_TCP`, source port `1234`, and destination port `4321`.
- If you want to protect all UDP traffic to a remote peer, create a broader SPD entry with the remote address and UDP protocol, and choose wildcard or broader port matching as appropriate for your policy design.
- If you want plaintext traffic, install a `POLICY_BYPASS` entry instead of `POLICY_APPLY`.
- If traffic must never be sent or accepted without IPsec, use `POLICY_APPLY` on the matching flow and ensure the inbound SPD is also provisioned.

One detail matters for dynamic policy updates:

- `ipsec_spd_lookup()` walks the SPD in list order and stops on the first match.
- `ipsec_spd_add()` appends new entries at the tail.
- Because of that, a catch-all `POLICY_BYPASS` entry added first will shadow any narrower `POLICY_APPLY` entry that you append later.

The socket API itself does not change. The SPD decides whether the traffic from that socket is protected.

## Typical startup sequence

At system startup or interface bring-up time:

1. Either allocate one `ipsec_lwip_adapter`, one `db_set_netif`, and four table arrays manually, or call `ipsec_lwip_adapter_attach_malloc(netif)`.
2. If you manage storage yourself, initialize the database set with `ipsec_spd_load_dbs()` or `ipsec_spd_init_dbs()`. The heap helper already allocates SAD/SPD arrays and still uses the static `db_set_netif` pool in [src/core/sa.c](src/core/sa.c).
3. Decide whether startup should be strict-protect, strict-drop, or explicit default-bypass.
4. Add outbound and inbound SAs.
5. Add outbound and inbound SPD entries and link them to the SAs with `ipsec_spd_add_sa()`.
6. Reset inbound replay windows with `ipsec_sad_reset_replay()` whenever you install or rekey an inbound SA.
7. Attach the adapter to the netif from lwIP core-locked context.
8. Use normal sockets on that netif.

## Recommended pattern: default bypass at startup, selective protection later

If your real system should behave like this:

1. bring the netif up with IPsec attached,
2. bypass most traffic by default,
3. later decide that one socket flow should use AH or ESP,

then the safest control-plane model is:

1. Install exactly one outbound catch-all `POLICY_BYPASS` entry during startup.
2. Do not rely on an empty outbound SPD as the default. The lwIP adapter treats that as a policy error, not as implicit bypass.
3. When you want to protect a new socket flow, rebuild the outbound SPD order so the narrow `POLICY_APPLY` rule comes before the catch-all bypass rule.
4. Add or update the matching inbound SA and inbound SPD rule for the protected flow.
5. Perform those updates from lwIP core-locked context, or on the tcpip thread, so packet lookup and policy mutation do not race.

In other words, the dynamic operation is not:

1. startup with catch-all bypass,
2. append a new apply rule later.

That does not work with the current SPD behavior, because the earlier catch-all bypass rule wins first.

The resulting outbound order must be:

1. all narrow `POLICY_APPLY` rules that should take precedence,
2. one catch-all `POLICY_BYPASS` rule last.

The core SA layer now provides small helpers for this exact pattern:

- `ipsec_spd_add_default_bypass()` installs one catch-all bypass rule for IPv4 or IPv6 if it is not already present.
- `ipsec_spd_add_ipv4_before_default_bypass()` adds one IPv4 rule and, if a catch-all bypass rule already exists, temporarily removes and restores it so the new rule ends up before the fallback bypass.
- `ipsec_spd_add_ipv6_before_default_bypass()` does the same for IPv6.

If you are protecting multiple flows over time, think of your control layer as owning a desired policy list and re-materializing the live SPD in priority order whenever that list changes.

## Control-plane workflow for on-the-fly socket protection

For one netif, keep a small control-plane model outside the IPsec core:

- a list of protected flows, each defined by address family, local/remote addresses, protocol, local port, remote port, mode, SPI, algorithms, and keys
- one remembered outbound catch-all bypass policy
- one update function that rewrites the live SPD/SAD state in deterministic order

The update flow should be:

1. Enter lwIP core-locked context.
2. Add or refresh the outbound SA and inbound SA for the new protected flow.
3. Add the narrow outbound `POLICY_APPLY` rule for that flow with `ipsec_spd_add_ipv4_before_default_bypass()` or `ipsec_spd_add_ipv6_before_default_bypass()`.
4. Add the narrow inbound `POLICY_APPLY` rule for that flow and link it to the inbound SA.
5. Reset inbound replay state on the inbound SA with `ipsec_sad_reset_replay()`.
6. Ensure the outbound family still has its catch-all `POLICY_BYPASS` fallback, for example with `ipsec_spd_add_default_bypass()`.
7. Leave lwIP core-locked context.

If you later remove protection from that socket flow, do the inverse:

1. enter lwIP core-locked context,
2. remove the flow-specific outbound and inbound SPD entries,
3. remove or retire the flow-specific SAs if they are no longer referenced,
4. keep the catch-all outbound bypass rule last.

## Socket selection strategy

Because there is no socket-level IPsec API, your application or control plane must make the target socket easy to identify in the SPD.

The most practical patterns are:

1. Bind the protected socket to a fixed local port, and match that local port plus the remote peer tuple in the SPD.
2. Reserve a dedicated remote port or remote peer address for protected traffic.
3. If multiple application sockets would otherwise look identical at the IP layer, separate them by netif, routing domain, or explicit local port assignment.

If the application lets the stack choose ephemeral local ports unpredictably, then a later SPD update may not be able to target the intended socket flow precisely enough.

## Example sequence: start bypassed, then protect one UDP socket

At startup:

1. Attach the adapter to the netif.
2. Add one outbound catch-all `POLICY_BYPASS` entry, for example with `ipsec_spd_add_default_bypass(IPSEC_AF_INET, &databases->outbound_spd)` and the IPv6 equivalent if that netif should also bypass unmatched IPv6 traffic.
3. Leave inbound SAD/SPD empty until you actually provision a protected flow.

Later, when the application decides that UDP traffic from local port `50000` to `192.168.1.20:4500` must use ESP transport mode:

1. Add the protected outbound rule ahead of the fallback bypass entry with `ipsec_spd_add_ipv4_before_default_bypass()`.
2. Add the outbound ESP SA.
3. Add the inbound ESP SA and call `ipsec_sad_reset_replay()` on it.
4. Use selectors matching local address, remote address, `IPSEC_PROTO_UDP`, source port `50000`, and destination port `4500`.
5. Link that outbound SPD entry to the outbound SA with `ipsec_spd_add_sa()`.
6. Add the matching inbound `POLICY_APPLY` rule.
7. Link that inbound SPD entry to the inbound SA.

After that, only the matched UDP socket flow is protected. Other outbound socket traffic still hits the last bypass rule and stays plaintext.

## Practical conclusion for one main netif

For the main protected netif, the simplest working model is:

1. install only an outbound default bypass rule during initialization,
2. do not install inbound default bypass rules, because inbound non-IPsec traffic should never be passed to IPsec in the first place,
3. when a protected socket flow is provisioned, add its outbound rule before the fallback bypass rule and add its matching inbound SA/SPD state,
4. keep using the helper layer from one control function instead of editing the live SPD directly from application code.

## Example: protect one TCP flow with IPv4 transport-mode AH

The following example shows the control-plane side. It provisions one outbound policy and one inbound policy for a TCP flow between `192.168.1.10:1234` and `192.168.1.20:4321`.

```c
#include <string.h>

#include "ipsec/ah.h"
#include "ipsec/ipsec.h"
#include "ipsec/sa.h"
#include "ipsec/util.h"
#include "netif/ipsec_lwip_adapter.h"

static sad_entry g_outbound_sa;
static sad_entry g_inbound_sa_template;

static void app_init_ah_sa(sad_entry *sa, __u32 peer_addr, __u32 spi)
{
    memset(sa, 0, sizeof(*sa));
    sa->dest = peer_addr;
    sa->dest_netaddr = ipsec_inet_addr("255.255.255.255");
    sa->spi = ipsec_htonl(spi);
    sa->protocol = IPSEC_PROTO_AH;
    sa->mode = IPSEC_TRANSPORT;
    sa->auth_alg = IPSEC_HMAC_SHA1;
    sa->path_mtu = 1450;
    sa->use_flag = IPSEC_USED;

    memcpy(sa->authkey, "01234567890123456789", IPSEC_AUTH_SHA1_KEY_LEN);
}

int app_ipsec_attach_ipv4_ah(struct netif *netif)
{
    ipsec_lwip_adapter *adapter;
    db_set_netif *databases;
    spd_entry *inbound_spd;
    spd_entry *outbound_spd;
    sad_entry *inbound_sa;

    app_init_ah_sa(&g_outbound_sa, ipsec_inet_addr("192.168.1.20"), 0x1001);
    app_init_ah_sa(&g_inbound_sa_template, ipsec_inet_addr("192.168.1.20"), 0x1001);

    adapter = ipsec_lwip_adapter_attach_malloc(netif);
    if(adapter == NULL)
    {
        return -1;
    }

    databases = adapter->databases;

    inbound_sa = ipsec_sad_add(&g_inbound_sa_template, &databases->inbound_sad);
    inbound_spd = ipsec_spd_add(ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("255.255.255.255"),
                                ipsec_inet_addr("192.168.1.20"), ipsec_inet_addr("255.255.255.255"),
                                IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY,
                                &databases->inbound_spd);
    outbound_spd = ipsec_spd_add(ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("255.255.255.255"),
                                 ipsec_inet_addr("192.168.1.20"), ipsec_inet_addr("255.255.255.255"),
                                 IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY,
                                 &databases->outbound_spd);
    if((inbound_sa == NULL) || (inbound_spd == NULL) || (outbound_spd == NULL))
    {
        ipsec_lwip_adapter_deinit(netif);
        return -1;
    }

    ipsec_sad_reset_replay(inbound_sa);
    ipsec_spd_add_sa(outbound_spd, &g_outbound_sa);
    ipsec_spd_add_sa(inbound_spd, inbound_sa);
    return 0;
}
```

This is the important part:

- The outbound SPD entry selects which locally generated socket traffic gets AH.
- The inbound SAD/SPD entries define what authenticated traffic is accepted back.
- The socket code still just opens and uses a TCP socket.

## Example: application socket code after IPsec is attached

Once the netif has been configured, the application uses sockets normally:

```c
int sock;
struct sockaddr_in remote_addr;

sock = socket(AF_INET, SOCK_STREAM, 0);
if(sock < 0)
{
    return -1;
}

memset(&remote_addr, 0, sizeof(remote_addr));
remote_addr.sin_family = AF_INET;
remote_addr.sin_port = htons(4321);
remote_addr.sin_addr.s_addr = inet_addr("192.168.1.20");

if(connect(sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
{
    close(sock);
    return -1;
}

send(sock, "hello", 5, 0);
recv(sock, buffer, sizeof(buffer), 0);
```

There is no IPsec-specific socket option in this flow. The traffic is protected because the SPD entry matches it.

## IPv6 usage

For IPv6, the model is the same.

The differences are:

- Use `ipsec_spd_add_ipv6()` and `ipsec_sad_set_ipv6()`.
- Pass IPv6 source and destination addresses to the lwIP adapter's IPv6 output path.
- Use normal IPv6 sockets in the application.

The test setup in [src/testing/structural/ipv6_test.c](src/testing/structural/ipv6_test.c#L156) shows the minimal SPD/SAD pattern for IPv6 policy matching.

## Tunnel mode versus transport mode from the application's point of view

From the application layer, both modes still use ordinary sockets.

The difference is in how you provision the SA:

- `IPSEC_TRANSPORT` protects the payload of the original packet and is usually what you want when the application talks directly to the final peer.
- `IPSEC_TUNNEL` wraps the whole original IP packet in a new outer IP header and is usually what you want for gateway-to-gateway or host-to-gateway VPN style links.

The socket API does not change between these modes. Only the SA and policy configuration changes.

## Rekeying and SA updates

If the application or control plane installs a new inbound SA:

1. Add or update the SA in the inbound SAD.
2. Link the matching SPD entry to the new SA.
3. Call `ipsec_sad_reset_replay()` on the inbound SA before it starts receiving traffic.

For outbound SAs there is no replay window to reset for correctness. Resetting a freshly initialized outbound template is harmless, but the required operation is on the inbound SA that will enforce anti-replay.

If you replace a database set entirely, re-attach the adapter with the new `db_set_netif *`, or call `ipsec_lwip_adapter_deinit(netif)` before creating a new heap-managed context.

## What to do if you want per-socket control

If you need something that feels like per-socket IPsec selection, the current library does not expose that directly.

The practical options are:

1. Use SPD entries that match the socket's local/remote address and port tuple closely.
2. Allocate separate netifs or routing domains if your platform wants coarse traffic separation.
3. Add a custom control layer above this library that translates application policy into SPD/SAD updates.

## Summary

For this codebase, "application uses IPsec with sockets" means:

1. Configure SA and SPD state for the netif.
2. Attach the adapter to the netif.
3. Keep using normal sockets.
4. Let the SPD decide which socket flows are bypassed, discarded, or protected.

That is the intended usage model for the current manual-keyed embedded IPsec stack.
