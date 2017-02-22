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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/ip.h"

#include "ipsec/debug.h"
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

static int ipsec_lwip_check_alignment(ipsec_lwip_adapter *adapter, int headroom, unsigned char **packet, int report_success)
{
	uintptr_t buffer_addr;
	uintptr_t packet_addr;
	unsigned int alignment;
	unsigned char *local_packet;

	if(adapter == NULL)
	{
		return 0;
	}

	if(packet == NULL)
	{
		packet = &local_packet;
	}

	alignment = (unsigned int)sizeof(void *);
	buffer_addr = (uintptr_t)(void *)adapter->work_buffer.bytes;
	packet_addr = buffer_addr + (uintptr_t)headroom;
	*packet = adapter->work_buffer.bytes + headroom;

	if(((buffer_addr % alignment) != 0U) || ((packet_addr % alignment) != 0U))
	{
		IPSEC_LOG_ERR("ipsec_lwip_check_alignment", IPSEC_STATUS_FAILURE,
				  ("misaligned work buffer: base=%p packet=%p align=%u headroom=%d",
				   (void *)adapter->work_buffer.bytes, (void *)*packet, alignment, headroom));
		return 0;
	}

	if(report_success)
	{
		IPSEC_LOG_MSG("ipsec_lwip_check_alignment",
				  ("work buffer aligned: base=%p packet=%p align=%u",
				   (void *)adapter->work_buffer.bytes, (void *)*packet, alignment));
	}

	return 1;
}

/*
 * The core IPsec code still expects one mutable, contiguous packet image with spare
 * headroom for tunnel headers and spare tailroom for ESP padding and ICV data.
 * The lwIP shim therefore flattens the incoming pbuf chain into a work buffer
 * before calling the core transform functions.
 */
static int ipsec_lwip_copy_to_buffer(struct pbuf *p, ipsec_lwip_adapter *adapter, int headroom, unsigned char **packet)
{
	if((p == NULL) || (adapter == NULL) || (packet == NULL))
	{
		return -1;
	}

	if(p->tot_len > IPSEC_MTU)
	{
		return -1;
	}

	if(!ipsec_lwip_check_alignment(adapter, headroom, packet, 0))
	{
		return -1;
	}

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

static void ipsec_lwip_adapter_init(ipsec_lwip_adapter *adapter, db_set_netif *databases)
{
	if(adapter == NULL)
	{
		return;
	}

	adapter->databases = databases;
	adapter->owned_inbound_spd = NULL;
	adapter->owned_outbound_spd = NULL;
	adapter->owned_inbound_sad = NULL;
	adapter->owned_outbound_sad = NULL;
	adapter->owns_memory = 0;
	memset(adapter->work_buffer.bytes, 0, sizeof(adapter->work_buffer.bytes));
	ipsec_lwip_check_alignment(adapter, IPSEC_LWIP_WORKBUF_HEADROOM, NULL, 0);
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

ipsec_lwip_adapter *ipsec_lwip_adapter_attach_malloc(struct netif *netif)
{
	ipsec_lwip_adapter *adapter;
	db_set_netif *databases;
	spd_entry *inbound_spd;
	spd_entry *outbound_spd;
	sad_entry *inbound_sad;
	sad_entry *outbound_sad;

	if(netif == NULL)
	{
		return NULL;
	}

	adapter = ipsec_lwip_adapter_get(netif);
	if(adapter != NULL)
	{
		return adapter;
	}

	adapter = (ipsec_lwip_adapter *)malloc(sizeof(*adapter));
	inbound_spd = (spd_entry *)malloc(sizeof(*inbound_spd) * IPSEC_MAX_SPD_ENTRIES);
	outbound_spd = (spd_entry *)malloc(sizeof(*outbound_spd) * IPSEC_MAX_SPD_ENTRIES);
	inbound_sad = (sad_entry *)malloc(sizeof(*inbound_sad) * IPSEC_MAX_SAD_ENTRIES);
	outbound_sad = (sad_entry *)malloc(sizeof(*outbound_sad) * IPSEC_MAX_SAD_ENTRIES);

	if((adapter == NULL) || (inbound_spd == NULL) || (outbound_spd == NULL) ||
	   (inbound_sad == NULL) || (outbound_sad == NULL))
	{
		free(outbound_sad);
		free(inbound_sad);
		free(outbound_spd);
		free(inbound_spd);
		free(adapter);
		return NULL;
	}

	memset(adapter, 0, sizeof(*adapter));
	memset(inbound_spd, 0, sizeof(*inbound_spd) * IPSEC_MAX_SPD_ENTRIES);
	memset(outbound_spd, 0, sizeof(*outbound_spd) * IPSEC_MAX_SPD_ENTRIES);
	memset(inbound_sad, 0, sizeof(*inbound_sad) * IPSEC_MAX_SAD_ENTRIES);
	memset(outbound_sad, 0, sizeof(*outbound_sad) * IPSEC_MAX_SAD_ENTRIES);

	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad);
	if(databases == NULL)
	{
		free(outbound_sad);
		free(inbound_sad);
		free(outbound_spd);
		free(inbound_spd);
		free(adapter);
		return NULL;
	}

	ipsec_lwip_adapter_init(adapter, databases);
	adapter->owned_inbound_spd = inbound_spd;
	adapter->owned_outbound_spd = outbound_spd;
	adapter->owned_inbound_sad = inbound_sad;
	adapter->owned_outbound_sad = outbound_sad;
	adapter->owns_memory = 1;
	ipsec_lwip_adapter_bind(netif, adapter);

	return adapter;
}

void ipsec_lwip_adapter_deinit(struct netif *netif)
{
	ipsec_lwip_adapter *adapter;
	db_set_netif *databases;

	if(netif == NULL)
	{
		return;
	}

	adapter = ipsec_lwip_adapter_get(netif);
	if(adapter == NULL)
	{
		return;
	}

	netif_set_client_data(netif, ipsec_lwip_get_client_data_id(), NULL);
	databases = adapter->databases;
	if(databases != NULL)
	{
		ipsec_spd_release_dbs(databases);
	}

	if(adapter->owns_memory)
	{
		free(adapter->owned_outbound_sad);
		free(adapter->owned_inbound_sad);
		free(adapter->owned_outbound_spd);
		free(adapter->owned_inbound_spd);
		free(adapter);
		return;
	}

	adapter->databases = NULL;
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
	struct pbuf *output;

	adapter = ipsec_lwip_adapter_get(inp);
	if((adapter == NULL) || (adapter->databases == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	packet_len = ipsec_lwip_copy_to_buffer(p, adapter, IPSEC_LWIP_WORKBUF_HEADROOM, &packet);
	if(packet_len < 0)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
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

static ipsec_lwip_action ipsec_lwip_output_common(unsigned char *packet, int packet_len,
									   ipsec_lwip_adapter *adapter,
									   struct pbuf **result,
									   spd_entry **out_spd)
{
	spd_entry *spd;

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

	if(spd->policy == POLICY_DISCARD)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_DISCARD;
	}

	*out_spd = spd;
	return IPSEC_LWIP_ACTION_DELIVER;
}

ipsec_lwip_action ipsec_lwip_output_ipv4(struct pbuf *p, struct netif *netif,
							 const ip4_addr_t *src, const ip4_addr_t *dst,
							 struct pbuf **result)
{
	ipsec_lwip_adapter *adapter;
	unsigned char *packet;
	int packet_len;
	int payload_offset;
	int payload_size;
	spd_entry *spd;
	struct pbuf *output;
	int status;
	ipsec_lwip_action action;

	adapter = ipsec_lwip_adapter_get(netif);
	if((adapter == NULL) || (adapter->databases == NULL) || (src == NULL) || (dst == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	packet_len = ipsec_lwip_copy_to_buffer(p, adapter, IPSEC_LWIP_WORKBUF_HEADROOM, &packet);
	if(packet_len < 0)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	spd = NULL;
	action = ipsec_lwip_output_common(packet, packet_len, adapter, result, &spd);
	if(action != IPSEC_LWIP_ACTION_DELIVER)
	{
		return action;
	}

	payload_offset = 0;
	payload_size = 0;
	status = ipsec_output(packet, packet_len, &payload_offset, &payload_size,
				  ip4_addr_get_u32(src), ip4_addr_get_u32(dst), spd);
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

ipsec_lwip_action ipsec_lwip_output_ipv6(struct pbuf *p, struct netif *netif,
							 const ip6_addr_t *src, const ip6_addr_t *dst,
							 struct pbuf **result)
{
	ipsec_lwip_adapter *adapter;
	unsigned char *packet;
	int packet_len;
	int payload_offset;
	int payload_size;
	spd_entry *spd;
	struct pbuf *output;
	int status;
	ipsec_lwip_action action;

	adapter = ipsec_lwip_adapter_get(netif);
	if((adapter == NULL) || (adapter->databases == NULL) || (src == NULL) || (dst == NULL))
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	packet_len = ipsec_lwip_copy_to_buffer(p, adapter, IPSEC_LWIP_WORKBUF_HEADROOM, &packet);
	if(packet_len < 0)
	{
		if(result != NULL)
		{
			*result = NULL;
		}
		return IPSEC_LWIP_ACTION_ERROR;
	}

	spd = NULL;
	action = ipsec_lwip_output_common(packet, packet_len, adapter, result, &spd);
	if(action != IPSEC_LWIP_ACTION_DELIVER)
	{
		return action;
	}

	payload_offset = 0;
	payload_size = 0;
	status = ipsec_output_ipv6(packet, packet_len, &payload_offset, &payload_size,
					   (const __u8 *)src, (const __u8 *)dst, spd);
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

#endif