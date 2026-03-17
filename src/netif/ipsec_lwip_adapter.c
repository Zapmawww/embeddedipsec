/*
 * embedded IPsec
 * Copyright (c) 2026 Zapmawww
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

#ifndef __NO_TCPIP_STACK__

#include <string.h>

#include "lwip/ip.h"

#include "netif/ipsec_lwip_adapter.h"

static u8_t ipsec_lwip_client_data_id;
static int ipsec_lwip_client_data_id_valid;

static u8_t ipsec_lwip_get_client_data_id(void)
{
	if(!ipsec_lwip_client_data_id_valid)
	{
		ipsec_lwip_client_data_id = netif_alloc_client_data_id();
		ipsec_lwip_client_data_id_valid = 1;
	}

	return ipsec_lwip_client_data_id;
}

static ipsec_lwip_adapter *ipsec_lwip_require_adapter(struct netif *netif)
{
	if(netif == NULL)
	{
		return NULL;
	}

	return ipsec_lwip_adapter_get(netif);
}

static ipsec_lwip_action ipsec_lwip_copy_outcome(struct pbuf *original, struct pbuf **result)
{
	if(result != NULL)
	{
		*result = original;
	}

	return IPSEC_LWIP_ACTION_BYPASS;
}

/*
 * The core IPsec code still expects one mutable, contiguous packet image with spare
 * headroom for tunnel headers and spare tailroom for ESP padding and ICV data.
 * The lwIP shim therefore flattens the incoming pbuf chain into a work buffer
 * before calling the core transform functions.
 */
static int ipsec_lwip_copy_to_buffer(struct pbuf *p, unsigned char *buffer, int headroom, unsigned char **packet)
{
	if((p == NULL) || (buffer == NULL) || (packet == NULL))
	{
		return -1;
	}

	if(p->tot_len > IPSEC_MTU)
	{
		return -1;
	}

	*packet = buffer + headroom;
	if(pbuf_copy_partial(p, *packet, p->tot_len, 0) != p->tot_len)
	{
		return -1;
	}

	return p->tot_len;
}

/*
 * Core transforms return an offset/length pair inside the caller-owned buffer.
 * The adapter converts that result back into a fresh pbuf so the surrounding
 * lwIP path can continue using normal pbuf ownership rules.
 */
static struct pbuf *ipsec_lwip_alloc_packet(const void *data, u16_t len)
{
	struct pbuf *packet;

	packet = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
	if(packet == NULL)
	{
		return NULL;
	}

	if(pbuf_take(packet, data, len) != ERR_OK)
	{
		pbuf_free(packet);
		return NULL;
	}

	return packet;
}

/*
 * Outbound processing is identical for AH/ESP and transport/tunnel mode at the
 * hook level: resolve one outbound SPD entry, interpret the policy, then hand
 * the packet to the requested core transform. The mode-specific packet surgery
 * stays inside ipsec_output()/ipsec_output_ipv6().
 */
static ipsec_lwip_action ipsec_lwip_transform_output(unsigned char *packet, int packet_len,
									 ipsec_lwip_adapter *adapter,
									 int (*transform)(unsigned char *, int, int *, int *, void const *, void const *, void *),
									 const void *src, const void *dst,
									 struct pbuf **result)
{
	int payload_offset;
	/*
	 * lwIP has already selected the egress netif, so the per-netif outbound SPD is
	 * the only policy database consulted here. A missing SPD entry is treated as an
	 * integration error rather than an implicit bypass.
	 */
	int payload_size;
	spd_entry *spd;
	struct pbuf *output;
	int status;

	payload_offset = 0;
	payload_size = 0;
	spd = ipsec_spd_lookup(packet, &adapter->databases->outbound_spd);
	if(spd == NULL)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	if(spd->policy == POLICY_BYPASS)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_BYPASS;
	}

	if((spd->policy == POLICY_DISCARD) || (spd->sa == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return spd->policy == POLICY_DISCARD ? IPSEC_LWIP_ACTION_DISCARD : IPSEC_LWIP_ACTION_ERROR;
	}

	status = transform(packet, packet_len, &payload_offset, &payload_size, src, dst, spd);
	if(status != IPSEC_STATUS_SUCCESS)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	output = ipsec_lwip_alloc_packet(packet + payload_offset, (u16_t)payload_size);
	if(output == NULL)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	if(result != NULL)
	{
		*result = output;
	}

	return IPSEC_LWIP_ACTION_DELIVER;
}

static void ipsec_lwip_adapter_init(ipsec_lwip_adapter *adapter, db_set_netif *databases)
{
	if(adapter == NULL)
	{
		return;
	}

	adapter->databases = databases;
	memset(adapter->work_buffer, 0, sizeof(adapter->work_buffer));
}

static void ipsec_lwip_adapter_bind(struct netif *netif, ipsec_lwip_adapter *adapter)
{
	if(netif == NULL)
	{
		return;
	}

	netif_set_client_data(netif, ipsec_lwip_get_client_data_id(), adapter);
}

void ipsec_lwip_adapter_attach(struct netif *netif, ipsec_lwip_adapter *adapter, db_set_netif *databases)
{
	ipsec_lwip_adapter_init(adapter, databases);
	ipsec_lwip_adapter_bind(netif, adapter);
}

ipsec_lwip_adapter *ipsec_lwip_adapter_get(const struct netif *netif)
{
	if(netif == NULL)
	{
		return NULL;
	}

	return (ipsec_lwip_adapter *)netif_get_client_data((struct netif *)netif, ipsec_lwip_get_client_data_id());
}

ipsec_lwip_action ipsec_lwip_input(struct pbuf *p, struct netif *inp, struct pbuf **result)
{
	ipsec_lwip_adapter *adapter;
	unsigned char *packet;
	int packet_len;
	int payload_offset;
	int payload_size;
	int status;
	spd_entry *spd;
	struct pbuf *output;

	adapter = ipsec_lwip_require_adapter(inp);

	if((adapter == NULL) || (adapter->databases == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	packet_len = ipsec_lwip_copy_to_buffer(p, adapter->work_buffer, IPSEC_LWIP_WORKBUF_HEADROOM, &packet);
	if(packet_len < 0)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	/*
	 * The inbound hook sees both protected AH/ESP traffic and ordinary plaintext IP
	 * traffic. Plaintext traffic still runs through the inbound SPD so a configured
	 * APPLY policy can reject packets that should have arrived protected.
	 */
	if((ipsec_packet_protocol(packet) != IPSEC_PROTO_AH) && (ipsec_packet_protocol(packet) != IPSEC_PROTO_ESP))
	{
		spd = ipsec_spd_lookup(packet, &adapter->databases->inbound_spd);
		if(spd == NULL)
		{
			if(result != NULL)
			{
				*result = NULL;
			}
			return IPSEC_LWIP_ACTION_ERROR;
		}

		if(spd->policy == POLICY_BYPASS)
		{
			return ipsec_lwip_copy_outcome(p, result);
		}

		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_DISCARD;
	}

	/*
	 * ipsec_input() rewrites the working buffer in place and reports where the inner
	 * packet now starts. That offset can be zero for transport mode or point into the
	 * middle of the buffer for tunnel decapsulation.
	 */
	payload_offset = 0;
	payload_size = 0;
	status = ipsec_input(packet, packet_len, &payload_offset, &payload_size, adapter->databases);
	if(status != IPSEC_STATUS_SUCCESS)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_DISCARD;
	}

	output = ipsec_lwip_alloc_packet(packet + payload_offset, (u16_t)payload_size);
	if(output == NULL)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	if(result != NULL)
	{
		*result = output;
	}

	return IPSEC_LWIP_ACTION_DELIVER;
}

static int ipsec_lwip_call_output_ipv4(unsigned char *packet, int packet_len, int *payload_offset,
									 int *payload_size, void const *src,
									 void const *dst, void *spd)
{
	return ipsec_output(packet, packet_len, payload_offset, payload_size,
				   *((const __u32 *)src), *((const __u32 *)dst), spd);
}

static int ipsec_lwip_call_output_ipv6(unsigned char *packet, int packet_len, int *payload_offset,
									 int *payload_size, void const *src,
									 void const *dst, void *spd)
{
	return ipsec_output_ipv6(packet, packet_len, payload_offset, payload_size,
					(const __u8 *)src, (const __u8 *)dst, spd);
}

ipsec_lwip_action ipsec_lwip_output_ipv4(struct pbuf *p, struct netif *netif,
							 const ip4_addr_t *src, const ip4_addr_t *dst,
							 struct pbuf **result)
{
	ipsec_lwip_adapter *adapter;
	unsigned char *packet;
	int packet_len;
	__u32 src_addr;
	__u32 dst_addr;

	adapter = ipsec_lwip_require_adapter(netif);

	if((adapter == NULL) || (adapter->databases == NULL) || (src == NULL) || (dst == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	packet_len = ipsec_lwip_copy_to_buffer(p, adapter->work_buffer, IPSEC_LWIP_WORKBUF_HEADROOM, &packet);
	if(packet_len < 0)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	src_addr = ip4_addr_get_u32(src);
	dst_addr = ip4_addr_get_u32(dst);
	/*
	 * The IPv4 and IPv6 wrappers only adapt lwIP address types. The actual policy
	 * and encapsulation path stays shared so AH/ESP and tunnel/transport mode use
	 * the same hook contract.
	 */
	return ipsec_lwip_transform_output(packet, packet_len, adapter, ipsec_lwip_call_output_ipv4,
					   &src_addr, &dst_addr, result);
}

ipsec_lwip_action ipsec_lwip_output_ipv6(struct pbuf *p, struct netif *netif,
							 const ip6_addr_t *src, const ip6_addr_t *dst,
							 struct pbuf **result)
{
	ipsec_lwip_adapter *adapter;
	unsigned char *packet;
	int packet_len;

	adapter = ipsec_lwip_require_adapter(netif);

	if((adapter == NULL) || (adapter->databases == NULL) || (src == NULL) || (dst == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	packet_len = ipsec_lwip_copy_to_buffer(p, adapter->work_buffer, IPSEC_LWIP_WORKBUF_HEADROOM, &packet);
	if(packet_len < 0)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	return ipsec_lwip_transform_output(packet, packet_len, adapter, ipsec_lwip_call_output_ipv6,
					   src, dst, result);
}

#endif