/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
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

static ipsec_lwip_action ipsec_lwip_copy_outcome(struct pbuf *original, struct pbuf **result)
{
	if(result != NULL)
	{
		*result = original;
	}

	return IPSEC_LWIP_ACTION_BYPASS;
}

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

static ipsec_lwip_action ipsec_lwip_transform_output(unsigned char *packet, int packet_len,
									 ipsec_lwip_adapter *adapter,
									 int (*transform)(unsigned char *, int, int *, int *, void const *, void const *, void *),
									 const void *src, const void *dst,
									 struct pbuf **result)
{
	int payload_offset;
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

void ipsec_lwip_adapter_init(ipsec_lwip_adapter *adapter, db_set_netif *databases)
{
	if(adapter == NULL)
	{
		return;
	}

	adapter->databases = databases;
	memset(adapter->work_buffer, 0, sizeof(adapter->work_buffer));
}

ipsec_lwip_action ipsec_lwip_input(struct pbuf *p, struct netif *inp,
						   ipsec_lwip_adapter *adapter, struct pbuf **result)
{
	unsigned char *packet;
	int packet_len;
	int payload_offset;
	int payload_size;
	int status;
	spd_entry *spd;
	struct pbuf *output;
	(void)inp;

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

ipsec_lwip_action ipsec_lwip_output_ipv4(struct pbuf *p, const ip4_addr_t *src,
							 const ip4_addr_t *dst,
							 ipsec_lwip_adapter *adapter,
							 struct pbuf **result)
{
	unsigned char *packet;
	int packet_len;
	__u32 src_addr;
	__u32 dst_addr;

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
	return ipsec_lwip_transform_output(packet, packet_len, adapter, ipsec_lwip_call_output_ipv4,
					   &src_addr, &dst_addr, result);
}

ipsec_lwip_action ipsec_lwip_output_ipv6(struct pbuf *p, const ip6_addr_t *src,
							 const ip6_addr_t *dst,
							 ipsec_lwip_adapter *adapter,
							 struct pbuf **result)
{
	unsigned char *packet;
	int packet_len;

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