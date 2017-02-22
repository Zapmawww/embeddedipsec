# Using IPsec From an Application

This guide explains how an application should use embedded IPsec when the network stack is lwIP and the application sends traffic through the normal socket API.

The important model is:

- The application does not enable IPsec by calling a socket-level `setsockopt()` API.
- Instead, a control/configuration layer provisions Security Associations (SAs) and Security Policy Database (SPD) entries for a netif.
- After that, the application keeps using normal sockets such as `socket()`, `bind()`, `send()`, `sendto()`, `recv()`, and `recvfrom()`.
- The lwIP hook layer decides whether each packet is bypassed, discarded, or protected with AH/ESP based on the SPD entry that matches the packet.

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

The socket API itself does not change. The SPD decides whether the traffic from that socket is protected.

## Typical startup sequence

At system startup or interface bring-up time:

1. Either allocate one `ipsec_lwip_adapter`, one `db_set_netif`, and four table arrays manually, or call `ipsec_lwip_adapter_attach_malloc(netif)`.
2. Initialize the database set with `ipsec_spd_load_dbs()` or `ipsec_spd_init_dbs()` if you manage storage yourself. The heap helper still uses the static `db_set_netif` pool in [src/core/sa.c](src/core/sa.c).
3. Add outbound and inbound SAs.
4. Add outbound and inbound SPD entries and link them to the SAs with `ipsec_spd_add_sa()`.
5. Reset inbound replay windows with `ipsec_sad_reset_replay()` whenever you install or rekey an inbound SA.
6. Attach the adapter to the netif from lwIP core-locked context.
7. Use normal sockets on that netif.

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
    ipsec_sad_reset_replay(&g_outbound_sa);
    ipsec_sad_reset_replay(&g_inbound_sa_template);

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
