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

#ifndef __IPSEC_LWIP_ADAPTER_H__
#define __IPSEC_LWIP_ADAPTER_H__

#ifndef __NO_TCPIP_STACK__

#include "lwip/err.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#include "ipsec/ipsec.h"
#include "ipsec/sa.h"

#define IPSEC_LWIP_WORKBUF_HEADROOM (IPSEC_HLEN)
#define IPSEC_LWIP_WORKBUF_TAILROOM (IPSEC_HLEN)
#define IPSEC_LWIP_WORKBUF_SIZE (IPSEC_MTU + IPSEC_LWIP_WORKBUF_HEADROOM + IPSEC_LWIP_WORKBUF_TAILROOM)

typedef enum ipsec_lwip_action_enum
{
	IPSEC_LWIP_ACTION_BYPASS = 0,
	IPSEC_LWIP_ACTION_DELIVER = 1,
	IPSEC_LWIP_ACTION_DISCARD = 2,
	IPSEC_LWIP_ACTION_ERROR = 3
} ipsec_lwip_action;

typedef struct ipsec_lwip_adapter_struct
{
	db_set_netif *databases;
	unsigned char work_buffer[IPSEC_LWIP_WORKBUF_SIZE];
} ipsec_lwip_adapter;

void ipsec_lwip_adapter_init(ipsec_lwip_adapter *adapter, db_set_netif *databases);

ipsec_lwip_action ipsec_lwip_input(struct pbuf *p, struct netif *inp,
						   ipsec_lwip_adapter *adapter, struct pbuf **result);

ipsec_lwip_action ipsec_lwip_output_ipv4(struct pbuf *p, const ip4_addr_t *src,
							 const ip4_addr_t *dst,
							 ipsec_lwip_adapter *adapter,
							 struct pbuf **result);

ipsec_lwip_action ipsec_lwip_output_ipv6(struct pbuf *p, const ip6_addr_t *src,
							 const ip6_addr_t *dst,
							 ipsec_lwip_adapter *adapter,
							 struct pbuf **result);

#endif

#endif