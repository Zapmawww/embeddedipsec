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

/*
 * This file is a porting-side integration test for a real lwIP environment.
 * It is intentionally not part of the standalone host build in this repository
 * because it depends on the target port's lwIP headers, socket layer, sys_arch,
 * and tcpip thread model.
 *
 * Test model:
 * - create one mocked point-to-point netif whose IPv4/IPv6 output callback only captures wire bytes
 * - configure IPsec through the exported SA/SPD and adapter APIs
 * - send a UDP datagram through the socket API after the real lwIP outbound IPsec hook has already run
 * - capture and verify the protected packet in the output stub
 * - loop the protected wire packet back through the normal lwIP ingress path
 * - receive the original payload on another UDP socket
 *
 * Assumptions that may need adjustment in a concrete lwIP port:
 * - the socket API is enabled and backed by the tcpip thread
 * - lwIP has already been initialized before porting_test_run() is called
 * - packets sent to the netif's own IPv4 address still traverse netif->output
 *   instead of being short-circuited before the device hook
 */

#ifndef __NO_TCPIP_STACK__

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "lwip/err.h"
#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

#include "ipsec/debug.h"
#include "ipsec/sa.h"
#include "ipsec/util.h"
#include "netif/ipsec_lwip_adapter.h"

#if !LWIP_SOCKET
#error porting-test.c requires LWIP_SOCKET.
#endif

#if !LWIP_UDP
#error porting-test.c requires LWIP_UDP.
#endif

#if !LWIP_IPV4 && !LWIP_IPV6
#error porting-test.c requires LWIP_IPV4 or LWIP_IPV6.
#endif

#define PORTING_TEST_LOCAL_IPV4      "192.0.2.1"
#define PORTING_TEST_NETMASK_IPV4    "255.255.255.0"
#define PORTING_TEST_LOCAL_IPV6      "2001:db8::1"
#define PORTING_TEST_PREFIXLEN_IPV6  (64)
#define PORTING_TEST_SEND_PORT       (23001)
#define PORTING_TEST_RECV_PORT       (23002)
#define PORTING_TEST_RECV_TIMEOUT_MS (2000)
#define PORTING_TEST_WIRE_MAX        (IPSEC_LWIP_WORKBUF_SIZE)

static const char porting_test_payload[] = "embeddedipsec-lwip-roundtrip";

static const __u8 porting_test_auth_md5_key[IPSEC_AUTH_MD5_KEY_LEN] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const __u8 porting_test_auth_sha1_key[IPSEC_AUTH_SHA1_KEY_LEN] = {
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
	0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34
};

/* 3DES sub-keys must satisfy DES odd-parity (each byte must have an odd number
 * of bits set). The bytes below are the classical NIST/RFC DES test vectors
 * and pass DES_set_key_checked(). */
static const __u8 porting_test_3des_key[IPSEC_3DES_KEY_LEN] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,  /* sub-key 1 */
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,  /* sub-key 2 */
	0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67   /* sub-key 3 */
};

static const __u8 porting_test_aes_key[IPSEC_AES_CBC_KEY_LEN] = {
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70
};

typedef struct porting_test_case_struct
{
	const char *name;
	__u8 addr_family;
	__u8 protocol;
	__u8 enc_alg;
	__u8 auth_alg;
	__u32 spi;
} porting_test_case;

static const porting_test_case porting_test_cases[] = {
#if IPSEC_ENABLE_AH && LWIP_IPV4
	{ "ipv4-ah-md5", IPSEC_AF_INET, IPSEC_PROTO_AH, 0, IPSEC_HMAC_MD5, 0x1001 },
	{ "ipv4-ah-sha1", IPSEC_AF_INET, IPSEC_PROTO_AH, 0, IPSEC_HMAC_SHA1, 0x1002 },
#endif
#if IPSEC_ENABLE_ESP && LWIP_IPV4
	{ "ipv4-esp-3des-md5", IPSEC_AF_INET, IPSEC_PROTO_ESP, IPSEC_3DES, IPSEC_HMAC_MD5, 0x1101 },
	{ "ipv4-esp-3des-sha1", IPSEC_AF_INET, IPSEC_PROTO_ESP, IPSEC_3DES, IPSEC_HMAC_SHA1, 0x1102 },
	{ "ipv4-esp-aes-sha1", IPSEC_AF_INET, IPSEC_PROTO_ESP, IPSEC_AES_CBC, IPSEC_HMAC_SHA1, 0x1103 },
#endif
#if IPSEC_ENABLE_AH && LWIP_IPV6
	{ "ipv6-ah-md5", IPSEC_AF_INET6, IPSEC_PROTO_AH, 0, IPSEC_HMAC_MD5, 0x1201 },
	{ "ipv6-ah-sha1", IPSEC_AF_INET6, IPSEC_PROTO_AH, 0, IPSEC_HMAC_SHA1, 0x1202 },
#endif
#if IPSEC_ENABLE_ESP && LWIP_IPV6
	{ "ipv6-esp-3des-md5", IPSEC_AF_INET6, IPSEC_PROTO_ESP, IPSEC_3DES, IPSEC_HMAC_MD5, 0x1301 },
	{ "ipv6-esp-3des-sha1", IPSEC_AF_INET6, IPSEC_PROTO_ESP, IPSEC_3DES, IPSEC_HMAC_SHA1, 0x1302 },
	{ "ipv6-esp-aes-sha1", IPSEC_AF_INET6, IPSEC_PROTO_ESP, IPSEC_AES_CBC, IPSEC_HMAC_SHA1, 0x1303 },
#endif
};

/*
 * One context owns the temporary netif, one adapter attachment, one wire capture
 * buffer, and the per-case SA/SPD state needed for a single round-trip.
 */

typedef struct porting_test_sync_struct
{
	sys_sem_t sem;
	err_t status;
} porting_test_sync;

typedef struct porting_test_context_struct
{
	struct netif netif;
	ipsec_lwip_adapter *adapter;
	const porting_test_case *test_case;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
	int tx_socket;
	int rx_socket;
	unsigned char wire_packet[PORTING_TEST_WIRE_MAX];
	u16_t wire_len;
	__u8 wire_protocol;
	__u32 wire_spi;
	unsigned int output_hits;
	unsigned char local_ipv6[16];
	unsigned char prefix_ipv6[16];
} porting_test_context;

static void porting_test_fail(porting_test_context *ctx, const char *message)
{
	const char *test_name;

	if(message == NULL)
	{
		return;
	}

	test_name = (ctx != NULL) && (ctx->test_case != NULL) && (ctx->test_case->name != NULL)
		? ctx->test_case->name
		: "unknown";
	tprintf("porting-test[%s]: %s\n", test_name, message);
}

static void porting_test_failf(porting_test_context *ctx, const char *format, ...)
{
	const char *test_name;
	char message[256];
	va_list args;
	int written;

	if(format == NULL)
	{
		return;
	}

	test_name = (ctx != NULL) && (ctx->test_case != NULL) && (ctx->test_case->name != NULL)
		? ctx->test_case->name
		: "unknown";

	va_start(args, format);
	written = vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	if(written < 0)
	{
		tprintf("porting-test[%s]: %s\n", test_name, format);
		return;
	}

	tprintf("porting-test[%s]: %s\n", test_name, message);
}

static void porting_test_dump_bytes(porting_test_context *ctx,
						 const char *label,
						 const unsigned char *data,
						 unsigned int len,
						 unsigned int max_len)
{
	unsigned int dump_len;
	unsigned int index;
	char ascii[17];

	if((label == NULL) || (data == NULL))
	{
		return;
	}

	dump_len = len;
	if(dump_len > max_len)
	{
		dump_len = max_len;
	}

	porting_test_failf(ctx, "%s: len=%u, showing=%u%s",
				   label,
				   len,
				   dump_len,
				   (dump_len < len) ? " (truncated)" : "");

	for(index = 0; index < dump_len; index += 16)
	{
		unsigned int chunk;
		unsigned int inner;

		chunk = dump_len - index;
		if(chunk > 16)
		{
			chunk = 16;
		}

		for(inner = 0; inner < chunk; inner++)
		{
			unsigned char ch = data[index + inner];

			ascii[inner] = ((ch >= 32U) && (ch <= 126U)) ? (char)ch : '.';
		}
		ascii[chunk] = '\0';

		tprintf("porting-test[%s]:   %04u:",
				((ctx != NULL) && (ctx->test_case != NULL) && (ctx->test_case->name != NULL))
					? ctx->test_case->name
					: "unknown",
				index);
		for(inner = 0; inner < chunk; inner++)
		{
			tprintf(" %02x", data[index + inner]);
		}
		for(; inner < 16; inner++)
		{
			tprintf("   ");
		}
		tprintf("  |%s|\n", ascii);
	}
}

static void porting_test_log_wire_state(porting_test_context *ctx, const char *prefix)
{
	if(ctx == NULL)
	{
		return;
	}

	porting_test_failf(ctx,
				   "%soutput_hits=%u, wire_len=%u, wire_protocol=%u, expected_protocol=%u, wire_spi=0x%08lx, expected_spi=0x%08lx",
				   (prefix != NULL) ? prefix : "",
				   ctx->output_hits,
				   (unsigned int)ctx->wire_len,
				   (unsigned int)ctx->wire_protocol,
				   (ctx->test_case != NULL) ? (unsigned int)ctx->test_case->protocol : 0U,
				   (unsigned long)ctx->wire_spi,
				   (unsigned long)((ctx->test_case != NULL) ? ipsec_htonl(ctx->test_case->spi) : 0U));

	if(ctx->wire_len != 0)
	{
		porting_test_dump_bytes(ctx, "captured wire packet", ctx->wire_packet, ctx->wire_len, 96);
	}
}

static void porting_test_log_ip_packet_state(porting_test_context *ctx,
						 const char *label,
						 const struct pbuf *packet)
{
	unsigned char packet_buffer[PORTING_TEST_WIRE_MAX];
	u16_t packet_len;

	if((label == NULL) || (packet == NULL))
	{
		return;
	}

	packet_len = pbuf_copy_partial((struct pbuf *)packet, packet_buffer, sizeof(packet_buffer), 0);
	porting_test_failf(ctx,
				   "%s: pbuf_len=%u, pbuf_tot_len=%u, copied_len=%u",
				   label,
				   (unsigned int)packet->len,
				   (unsigned int)packet->tot_len,
				   (unsigned int)packet_len);

	if(packet_len != 0)
	{
		porting_test_dump_bytes(ctx, label, packet_buffer, packet_len, 96);
	}
}

static void porting_test_log_socket_errno(porting_test_context *ctx, const char *operation)
{
	porting_test_failf(ctx,
				   "%s failed, errno=%d",
				   (operation != NULL) ? operation : "socket operation",
				   errno);
}

static struct pbuf *porting_test_clone_pbuf(const struct pbuf *source)
{
	struct pbuf *copy;

	if(source == NULL)
	{
		return NULL;
	}

	copy = pbuf_alloc(PBUF_RAW, source->tot_len, PBUF_RAM);
	if(copy == NULL)
	{
		return NULL;
	}

	if(pbuf_copy_partial((struct pbuf *)source, copy->payload, source->tot_len, 0) != source->tot_len)
	{
		pbuf_free(copy);
		return NULL;
	}

	return copy;
}

static void porting_test_copy_auth_key(sad_entry *sa, __u8 auth_alg)
{
	if(auth_alg == IPSEC_HMAC_MD5)
	{
		memcpy(sa->authkey, porting_test_auth_md5_key, sizeof(porting_test_auth_md5_key));
		return;
	}

	memcpy(sa->authkey, porting_test_auth_sha1_key, sizeof(porting_test_auth_sha1_key));
}

static void porting_test_copy_enc_key(sad_entry *sa, __u8 enc_alg)
{
	if(enc_alg == IPSEC_AES_CBC)
	{
		memcpy(sa->enckey, porting_test_aes_key, sizeof(porting_test_aes_key));
		return;
	}

	if(enc_alg == IPSEC_3DES)
	{
		memcpy(sa->enckey, porting_test_3des_key, sizeof(porting_test_3des_key));
	}
}

static void porting_test_init_ipv6_mask(unsigned char *mask, unsigned int prefix_len)
{
	unsigned int index;

	if(mask == NULL)
	{
		return;
	}

	memset(mask, 0, 16);
	for(index = 0; index < 16; index++)
	{
		if(prefix_len >= 8U)
		{
			mask[index] = 0xff;
			prefix_len -= 8U;
		}
		else if(prefix_len != 0U)
		{
			mask[index] = (__u8)(0xffU << (8U - prefix_len));
			prefix_len = 0U;
		}
	}
}

static int porting_test_parse_ipv6(unsigned char *dst, const char *text)
{
	ip6_addr_t addr;

	if((dst == NULL) || (text == NULL))
	{
		return -1;
	}

	if(!ip6addr_aton(text, &addr))
	{
		return -1;
	}

	memcpy(dst, &addr, 16);
	return 0;
}

/*
 * The harness reinjects captured packets through tcpip_input() so the real
 * ip4_input()/ip6_input() path and the port's installed inbound hook run on the
 * tcpip thread instead of being bypassed by a direct adapter call.
 */
static err_t porting_test_inject_wire_packet(porting_test_context *ctx, struct pbuf *wire_packet)
{
	if((ctx == NULL) || (wire_packet == NULL))
	{
		return ERR_ARG;
	}

	return tcpip_input(wire_packet, &ctx->netif);
}

static void porting_test_init_sa(sad_entry *sa, const porting_test_case *test_case, __u32 peer_addr)
{
	memset(sa, 0, sizeof(*sa));
	sa->dest = peer_addr;
	sa->dest_netaddr = ipsec_inet_addr("255.255.255.255");
	sa->spi = ipsec_htonl(test_case->spi);
	sa->protocol = test_case->protocol;
	sa->mode = IPSEC_TRANSPORT;
	sa->path_mtu = 1450;
	sa->use_flag = IPSEC_USED;
	sa->replay_win = IPSEC_SEQ_MAX_WINDOW;
	sa->auth_alg = test_case->auth_alg;
	porting_test_copy_auth_key(sa, test_case->auth_alg);

	if(test_case->protocol == IPSEC_PROTO_ESP)
	{
		sa->enc_alg = test_case->enc_alg;
		porting_test_copy_enc_key(sa, test_case->enc_alg);
	}
}

static void porting_test_init_sa_ipv6(sad_entry *sa,
					   const porting_test_case *test_case,
					   const unsigned char *peer_addr,
					   const unsigned char *peer_prefix)
{
	porting_test_init_sa(sa, test_case, 0);
	ipsec_sad_set_ipv6(sa, peer_addr, peer_prefix);
}

static int porting_test_configure_ipsec(porting_test_context *ctx)
{
	__u32 local_addr;
	spd_entry *outbound_spd;
	spd_entry *inbound_spd;
	sad_entry *inbound_sa;
	db_set_netif *databases;

	if((ctx == NULL) || (ctx->adapter == NULL) || (ctx->adapter->databases == NULL))
	{
		return -1;
	}

	if(ctx->test_case->addr_family == IPSEC_AF_INET6)
	{
		spd_entry *outbound_spd_ipv6;
		spd_entry *inbound_spd_ipv6;

		/* IPv6 cases reuse the same harness flow, but provision IPv6 addresses and selectors. */
		databases = ctx->adapter->databases;
		porting_test_init_sa_ipv6(&ctx->outbound_sa, ctx->test_case, ctx->local_ipv6, ctx->prefix_ipv6);
		porting_test_init_sa_ipv6(&ctx->inbound_sa_template, ctx->test_case, ctx->local_ipv6, ctx->prefix_ipv6);
		ipsec_sad_reset_replay(&ctx->outbound_sa);
		ipsec_sad_reset_replay(&ctx->inbound_sa_template);

		inbound_sa = ipsec_sad_add(&ctx->inbound_sa_template, &databases->inbound_sad);
		outbound_spd_ipv6 = ipsec_spd_add_ipv6(ctx->local_ipv6, ctx->prefix_ipv6,
							  ctx->local_ipv6, ctx->prefix_ipv6,
							  IPSEC_PROTO_UDP,
							  ipsec_htons(PORTING_TEST_SEND_PORT),
							  ipsec_htons(PORTING_TEST_RECV_PORT),
							  POLICY_APPLY,
							  &databases->outbound_spd);
		inbound_spd_ipv6 = ipsec_spd_add_ipv6(ctx->local_ipv6, ctx->prefix_ipv6,
							 ctx->local_ipv6, ctx->prefix_ipv6,
							 IPSEC_PROTO_UDP,
							 ipsec_htons(PORTING_TEST_SEND_PORT),
							 ipsec_htons(PORTING_TEST_RECV_PORT),
							 POLICY_APPLY,
							 &databases->inbound_spd);
		if((inbound_sa == NULL) || (outbound_spd_ipv6 == NULL) || (inbound_spd_ipv6 == NULL))
		{
			return -1;
		}

		if((ipsec_spd_add_sa(outbound_spd_ipv6, &ctx->outbound_sa) != IPSEC_STATUS_SUCCESS) ||
		   (ipsec_spd_add_sa(inbound_spd_ipv6, inbound_sa) != IPSEC_STATUS_SUCCESS))
		{
			return -1;
		}

		return 0;
	}

	databases = ctx->adapter->databases;
	local_addr = ipsec_inet_addr(PORTING_TEST_LOCAL_IPV4);

	porting_test_init_sa(&ctx->outbound_sa, ctx->test_case, local_addr);
	porting_test_init_sa(&ctx->inbound_sa_template, ctx->test_case, local_addr);
	ipsec_sad_reset_replay(&ctx->outbound_sa);
	ipsec_sad_reset_replay(&ctx->inbound_sa_template);

	inbound_sa = ipsec_sad_add(&ctx->inbound_sa_template, &databases->inbound_sad);
	outbound_spd = ipsec_spd_add(local_addr, ipsec_inet_addr("255.255.255.255"),
							 local_addr, ipsec_inet_addr("255.255.255.255"),
							 IPSEC_PROTO_UDP,
							 ipsec_htons(PORTING_TEST_SEND_PORT),
							 ipsec_htons(PORTING_TEST_RECV_PORT),
							 POLICY_APPLY,
							 &databases->outbound_spd);
	inbound_spd = ipsec_spd_add(local_addr, ipsec_inet_addr("255.255.255.255"),
							local_addr, ipsec_inet_addr("255.255.255.255"),
							IPSEC_PROTO_UDP,
							ipsec_htons(PORTING_TEST_SEND_PORT),
							ipsec_htons(PORTING_TEST_RECV_PORT),
							POLICY_APPLY,
							&databases->inbound_spd);
	if((inbound_sa == NULL) || (outbound_spd == NULL) || (inbound_spd == NULL))
	{
		return -1;
	}

	if((ipsec_spd_add_sa(outbound_spd, &ctx->outbound_sa) != IPSEC_STATUS_SUCCESS) ||
	   (ipsec_spd_add_sa(inbound_spd, inbound_sa) != IPSEC_STATUS_SUCCESS))
	{
		return -1;
	}

	return 0;
}

static err_t porting_test_netif_output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *dst)
{
	porting_test_context *ctx;

	ctx = (porting_test_context *)netif->state;
	if((ctx == NULL) || (packet == NULL) || (dst == NULL))
	{
		return ERR_IF;
	}

	ctx->output_hits++;
	ctx->wire_len = (u16_t)pbuf_copy_partial(packet, ctx->wire_packet, sizeof(ctx->wire_packet), 0);
	if(ctx->wire_len == 0)
	{
		porting_test_failf(ctx,
				   "unable to capture wire packet: packet_len=%u, packet_tot_len=%u, dst=0x%08lx",
				   (unsigned int)packet->len,
				   (unsigned int)packet->tot_len,
				   (unsigned long)ip4_addr_get_u32(dst));
		return ERR_IF;
	}

	ctx->wire_protocol = ipsec_packet_protocol(ctx->wire_packet);
	ctx->wire_spi = ipsec_sad_get_spi(ctx->wire_packet);

	return ERR_OK;
}

#if LWIP_IPV6
static err_t porting_test_netif_output_ip6(struct netif *netif, struct pbuf *packet, const ip6_addr_t *dst)
{
	porting_test_context *ctx;

	ctx = (porting_test_context *)netif->state;
	if((ctx == NULL) || (packet == NULL) || (dst == NULL))
	{
		return ERR_IF;
	}

	ctx->output_hits++;
	ctx->wire_len = (u16_t)pbuf_copy_partial(packet, ctx->wire_packet, sizeof(ctx->wire_packet), 0);
	if(ctx->wire_len == 0)
	{
		porting_test_failf(ctx,
				   "unable to capture IPv6 wire packet: packet_len=%u, packet_tot_len=%u",
				   (unsigned int)packet->len,
				   (unsigned int)packet->tot_len);
		return ERR_IF;
	}

	ctx->wire_protocol = ipsec_packet_protocol(ctx->wire_packet);
	ctx->wire_spi = ipsec_sad_get_spi(ctx->wire_packet);
	return ERR_OK;
}
#endif


static void porting_test_loopback_on_tcpip(void *arg)
{
	porting_test_context *ctx;
	struct pbuf *wire_packet;
	err_t input_status;

	ctx = (porting_test_context *)arg;
	if((ctx == NULL) || (ctx->wire_len == 0))
	{
		porting_test_fail(ctx, "no captured wire packet available for loopback");
		porting_test_log_wire_state(ctx, "loopback state: ");
		return;
	}

	wire_packet = pbuf_alloc(PBUF_RAW, ctx->wire_len, PBUF_RAM);
	if(wire_packet == NULL)
	{
		porting_test_failf(ctx, "unable to allocate loopback wire packet: wire_len=%u", (unsigned int)ctx->wire_len);
		porting_test_log_wire_state(ctx, "loopback state: ");
		return;
	}

	if(pbuf_take(wire_packet, ctx->wire_packet, ctx->wire_len) != ERR_OK)
	{
		pbuf_free(wire_packet);
		porting_test_failf(ctx, "unable to populate loopback wire packet: wire_len=%u", (unsigned int)ctx->wire_len);
		porting_test_log_wire_state(ctx, "loopback state: ");
		return;
	}

	/*
	 * Inject the wire packet through tcpip_input() so the real lwIP ingress path
	 * and its inbound IPsec hook process it on the tcpip thread. Do NOT call
	 * ipsec_lwip_input() here — the hook installed in lwIP will do that
	 * automatically, just as the outbound hook handles protection on the send path.
	 */
	input_status = porting_test_inject_wire_packet(ctx, wire_packet);
	if(input_status != ERR_OK)
	{
		porting_test_failf(ctx,
				   "tcpip_input() rejected the wire packet: status=%d, wire_len=%u",
				   (int)input_status,
				   (unsigned int)ctx->wire_len);
		porting_test_log_wire_state(ctx, "loopback state: ");
		pbuf_free(wire_packet);
		return;
	}
}

static err_t porting_test_netif_init(struct netif *netif)
{
	porting_test_context *ctx;

	if(netif == NULL)
	{
		return ERR_ARG;
	}

	ctx = (porting_test_context *)netif->state;

	netif->name[0] = 'p';
	netif->name[1] = 't';
	netif->output = porting_test_netif_output;
	if((ctx != NULL) && (ctx->test_case != NULL) && (ctx->test_case->addr_family == IPSEC_AF_INET6))
	{
#if LWIP_IPV6
		netif->output_ip6 = porting_test_netif_output_ip6;
		netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;
#else
		return ERR_ARG;
#endif
	}
	else
	{
		netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;
	}
	netif->mtu = 1500;

	return ERR_OK;
}

static void porting_test_sync_signal(void *arg)
{
	porting_test_sync *sync = (porting_test_sync *)arg;

	if(sync != NULL)
	{
		sync->status = ERR_OK;
		sys_sem_signal(&sync->sem);
	}
}

static void porting_test_setup_on_tcpip(void *arg)
{
	porting_test_context *ctx = (porting_test_context *)arg;
	ip4_addr_t ipaddr;
	ip4_addr_t netmask;
	ip4_addr_t gateway;
	err_t ip6_status;
	s8_t ip6_index;

	if(ctx == NULL)
	{
		return;
	}

	if((ctx->test_case != NULL) && (ctx->test_case->addr_family == IPSEC_AF_INET6))
	{
#if LWIP_IPV6
		ip6_addr_t local_addr6;

		if((porting_test_parse_ipv6(ctx->local_ipv6, PORTING_TEST_LOCAL_IPV6) != 0))
		{
			porting_test_fail(ctx, "unable to parse local IPv6 address");
			return;
		}
		memcpy(&local_addr6, ctx->local_ipv6, sizeof(local_addr6));
		porting_test_init_ipv6_mask(ctx->prefix_ipv6, PORTING_TEST_PREFIXLEN_IPV6);
		if(netif_add(&ctx->netif, NULL, NULL, NULL, ctx, porting_test_netif_init, tcpip_input) == NULL)
		{
			porting_test_fail(ctx, "netif_add() failed for IPv6");
			return;
		}
		netif_create_ip6_linklocal_address(&ctx->netif, 1);
		/* netif_add_ip6_address() chooses the concrete slot; mark that exact slot preferred. */
		ip6_index = -1;
		ip6_status = netif_add_ip6_address(&ctx->netif, &local_addr6, &ip6_index);
		if((ip6_status != ERR_OK) || (ip6_index < 0))
		{
			porting_test_fail(ctx, "netif_add_ip6_address() failed");
			netif_remove(&ctx->netif);
			return;
		}
		netif_ip6_addr_set_state(&ctx->netif, ip6_index, IP6_ADDR_PREFERRED);
#else
		porting_test_fail(ctx, "IPv6 test case requested but LWIP_IPV6 is disabled");
		return;
#endif
	}
	else
	{
#if LWIP_IPV4
		IP4_ADDR(&ipaddr, 192, 0, 2, 1);
		IP4_ADDR(&netmask, 255, 255, 255, 0);
		IP4_ADDR(&gateway, 0, 0, 0, 0);

		if(netif_add(&ctx->netif, &ipaddr, &netmask, &gateway, ctx, porting_test_netif_init, tcpip_input) == NULL)
		{
			porting_test_fail(ctx, "netif_add() failed");
			return;
		}
#else
		porting_test_fail(ctx, "IPv4 test case requested but LWIP_IPV4 is disabled");
		return;
#endif
	}

	netif_set_default(&ctx->netif);
	netif_set_link_up(&ctx->netif);
	netif_set_up(&ctx->netif);

	ctx->adapter = ipsec_lwip_adapter_attach_malloc(&ctx->netif);
	if(ctx->adapter == NULL)
	{
		porting_test_fail(ctx, "ipsec_lwip_adapter_attach_malloc() failed");
		netif_remove(&ctx->netif);
		return;
	}

	if(porting_test_configure_ipsec(ctx) != 0)
	{
		porting_test_fail(ctx, "unable to configure SA/SPD state");
		ipsec_lwip_adapter_deinit(&ctx->netif);
		netif_remove(&ctx->netif);
		ctx->adapter = NULL;
	}
}

static void porting_test_teardown_on_tcpip(void *arg)
{
	porting_test_context *ctx = (porting_test_context *)arg;

	if(ctx == NULL)
	{
		return;
	}

	if(ctx->adapter != NULL)
	{
		ipsec_lwip_adapter_deinit(&ctx->netif);
		ctx->adapter = NULL;
	}

	netif_set_down(&ctx->netif);
	netif_remove(&ctx->netif);
}

static int porting_test_call_tcpip(void (*callback)(void *), void *arg)
{
	porting_test_sync sync;
	err_t status;

	if(sys_sem_new(&sync.sem, 0) != ERR_OK)
	{
		return -1;
	}

	sync.status = ERR_IF;
	status = tcpip_callback_with_block(callback, arg, 1);
	if(status != ERR_OK)
	{
		sys_sem_free(&sync.sem);
		return -1;
	}

	status = tcpip_callback_with_block(porting_test_sync_signal, &sync, 1);
	if(status != ERR_OK)
	{
		sys_sem_free(&sync.sem);
		return -1;
	}

	sys_arch_sem_wait(&sync.sem, 0);
	sys_sem_free(&sync.sem);
	return 0;
}

static int porting_test_prepare_sockets(porting_test_context *ctx)
{
	struct sockaddr_in6 local_addr6;
	struct sockaddr_in6 recv_addr6;
	struct sockaddr_in local_addr;
	struct sockaddr_in recv_addr;
	int timeout_ms;

	/* Each case uses the native socket family so the outer packet addresses match the SPD selectors. */
	ctx->tx_socket = lwip_socket((ctx->test_case->addr_family == IPSEC_AF_INET6) ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	ctx->rx_socket = lwip_socket((ctx->test_case->addr_family == IPSEC_AF_INET6) ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if((ctx->tx_socket < 0) || (ctx->rx_socket < 0))
	{
		porting_test_failf(ctx,
				   "unable to create UDP sockets: tx_socket=%d, rx_socket=%d",
				   ctx->tx_socket,
				   ctx->rx_socket);
		porting_test_log_socket_errno(ctx, "lwip_socket()");
		return -1;
	}

	timeout_ms = PORTING_TEST_RECV_TIMEOUT_MS;
	if(lwip_setsockopt(ctx->rx_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout_ms, sizeof(timeout_ms)) < 0)
	{
		porting_test_failf(ctx, "unable to set receive timeout: timeout_ms=%d, rx_socket=%d", timeout_ms, ctx->rx_socket);
		porting_test_log_socket_errno(ctx, "lwip_setsockopt(SO_RCVTIMEO)");
		return -1;
	}

	if(ctx->test_case->addr_family == IPSEC_AF_INET6)
	{
		memset(&local_addr6, 0, sizeof(local_addr6));
		local_addr6.sin6_family = AF_INET6;
		local_addr6.sin6_port = htons(PORTING_TEST_SEND_PORT);
		memcpy(&local_addr6.sin6_addr, ctx->local_ipv6, sizeof(ctx->local_ipv6));
		if(lwip_bind(ctx->tx_socket, (struct sockaddr *)&local_addr6, sizeof(local_addr6)) < 0)
		{
			porting_test_failf(ctx,
					   "unable to bind IPv6 sender socket: socket=%d, port=%u",
					   ctx->tx_socket,
					   (unsigned int)PORTING_TEST_SEND_PORT);
			porting_test_log_socket_errno(ctx, "lwip_bind(sender IPv6)");
			return -1;
		}

		memset(&recv_addr6, 0, sizeof(recv_addr6));
		recv_addr6.sin6_family = AF_INET6;
		recv_addr6.sin6_port = htons(PORTING_TEST_RECV_PORT);
		memcpy(&recv_addr6.sin6_addr, ctx->local_ipv6, sizeof(ctx->local_ipv6));
		if(lwip_bind(ctx->rx_socket, (struct sockaddr *)&recv_addr6, sizeof(recv_addr6)) < 0)
		{
			porting_test_failf(ctx,
					   "unable to bind IPv6 receiver socket: socket=%d, port=%u",
					   ctx->rx_socket,
					   (unsigned int)PORTING_TEST_RECV_PORT);
			porting_test_log_socket_errno(ctx, "lwip_bind(receiver IPv6)");
			return -1;
		}

		return 0;
	}

#if LWIP_IPV4
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(PORTING_TEST_SEND_PORT);
	local_addr.sin_addr.s_addr = inet_addr(PORTING_TEST_LOCAL_IPV4);
	if(lwip_bind(ctx->tx_socket, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
	{
		porting_test_failf(ctx,
				   "unable to bind sender socket: socket=%d, addr=%s:%u",
				   ctx->tx_socket,
				   PORTING_TEST_LOCAL_IPV4,
				   (unsigned int)PORTING_TEST_SEND_PORT);
		porting_test_log_socket_errno(ctx, "lwip_bind(sender)");
		return -1;
	}

	memset(&recv_addr, 0, sizeof(recv_addr));
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_port = htons(PORTING_TEST_RECV_PORT);
	recv_addr.sin_addr.s_addr = inet_addr(PORTING_TEST_LOCAL_IPV4);
	if(lwip_bind(ctx->rx_socket, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0)
	{
		porting_test_failf(ctx,
				   "unable to bind receiver socket: socket=%d, addr=%s:%u",
				   ctx->rx_socket,
				   PORTING_TEST_LOCAL_IPV4,
				   (unsigned int)PORTING_TEST_RECV_PORT);
		porting_test_log_socket_errno(ctx, "lwip_bind(receiver)");
		return -1;
	}

	return 0;
#else
	porting_test_fail(ctx, "IPv4 socket path requested but LWIP_IPV4 is disabled");
	return -1;
#endif
}

static int porting_test_run_roundtrip(porting_test_context *ctx)
{
	struct sockaddr_in6 dst_addr6;
	struct sockaddr_in dst_addr;
	char recv_buffer[128];
	int recv_len;
	int send_len;

	/* The send path is family-specific, but the protection and verification flow is shared. */
	if(ctx->test_case->addr_family == IPSEC_AF_INET6)
	{
		memset(&dst_addr6, 0, sizeof(dst_addr6));
		dst_addr6.sin6_family = AF_INET6;
		dst_addr6.sin6_port = htons(PORTING_TEST_RECV_PORT);
		memcpy(&dst_addr6.sin6_addr, ctx->local_ipv6, sizeof(ctx->local_ipv6));
		send_len = lwip_sendto(ctx->tx_socket,
				       porting_test_payload,
				       sizeof(porting_test_payload) - 1,
				       0,
				       (struct sockaddr *)&dst_addr6,
				       sizeof(dst_addr6));
	}
	#if LWIP_IPV4
	else
	{
		memset(&dst_addr, 0, sizeof(dst_addr));
		dst_addr.sin_family = AF_INET;
		dst_addr.sin_port = htons(PORTING_TEST_RECV_PORT);
		dst_addr.sin_addr.s_addr = inet_addr(PORTING_TEST_LOCAL_IPV4);
		send_len = lwip_sendto(ctx->tx_socket,
				       porting_test_payload,
				       sizeof(porting_test_payload) - 1,
				       0,
				       (struct sockaddr *)&dst_addr,
				       sizeof(dst_addr));
	}
	#else
	else
	{
		porting_test_fail(ctx, "IPv4 send path requested but LWIP_IPV4 is disabled");
		return -1;
	}
	#endif

	if(send_len != (int)(sizeof(porting_test_payload) - 1))
	{
		porting_test_failf(ctx,
				   "UDP send failed: socket=%d, payload_len=%u, family=%s, dst_port=%u",
				   ctx->tx_socket,
				   (unsigned int)(sizeof(porting_test_payload) - 1),
				   (ctx->test_case->addr_family == IPSEC_AF_INET6) ? "AF_INET6" : "AF_INET",
				   (unsigned int)PORTING_TEST_RECV_PORT);
		porting_test_log_socket_errno(ctx, "lwip_sendto()");
		return -1;
	}

	if(ctx->output_hits == 0)
	{
		porting_test_fail(ctx, "socket traffic did not reach netif output");
		porting_test_log_wire_state(ctx, "post-send state: ");
		return -1;
	}

	if((ctx->wire_protocol != ctx->test_case->protocol) ||
	   (ctx->wire_spi != ipsec_htonl(ctx->test_case->spi)))
	{
		porting_test_fail(ctx, "protected packet verification failed on output path");
		porting_test_log_wire_state(ctx, "wire verification: ");
		return -1;
	}

	if(porting_test_call_tcpip(porting_test_loopback_on_tcpip, ctx) != 0)
	{
		porting_test_fail(ctx, "tcpip loopback callback failed");
		return -1;
	}

	recv_len = lwip_recv(ctx->rx_socket, recv_buffer, sizeof(recv_buffer), 0);
	if(recv_len != (int)(sizeof(porting_test_payload) - 1))
	{
		porting_test_failf(ctx,
				   "receiver socket did not get the expected payload length: actual=%d, expected=%u",
				   recv_len,
				   (unsigned int)(sizeof(porting_test_payload) - 1));
		if(recv_len < 0)
		{
			porting_test_log_socket_errno(ctx, "lwip_recv()");
		}
		else
		{
			porting_test_dump_bytes(ctx,
						"received payload",
						(const unsigned char *)recv_buffer,
						(unsigned int)recv_len,
						96);
		}
		porting_test_dump_bytes(ctx,
					"expected payload",
					(const unsigned char *)porting_test_payload,
					(unsigned int)(sizeof(porting_test_payload) - 1),
					96);
		porting_test_log_wire_state(ctx, "receive mismatch state: ");
		return -1;
	}

	if(memcmp(recv_buffer, porting_test_payload, sizeof(porting_test_payload) - 1) != 0)
	{
		porting_test_failf(ctx,
				   "receiver socket payload mismatch: len=%d",
				   recv_len);
		porting_test_dump_bytes(ctx,
					"received payload",
					(const unsigned char *)recv_buffer,
					(unsigned int)recv_len,
					96);
		porting_test_dump_bytes(ctx,
					"expected payload",
					(const unsigned char *)porting_test_payload,
					(unsigned int)(sizeof(porting_test_payload) - 1),
					96);
		return -1;
	}

	return 0;
}

static int porting_test_run_case(const porting_test_case *test_case)
{
	porting_test_context ctx;
	int result;

	memset(&ctx, 0, sizeof(ctx));
	ctx.test_case = test_case;
	ctx.tx_socket = -1;
	ctx.rx_socket = -1;

	if(porting_test_call_tcpip(porting_test_setup_on_tcpip, &ctx) != 0)
	{
		tprintf("porting-test[%s]: setup callback failed\n", test_case->name);
		return 1;
	}

	if(ctx.adapter == NULL)
	{
		tprintf("porting-test[%s]: adapter setup failed\n", test_case->name);
		return 1;
	}

	if(porting_test_prepare_sockets(&ctx) != 0)
	{
		tprintf("porting-test[%s]: socket setup failed\n", test_case->name);
		if(ctx.tx_socket >= 0)
		{
			lwip_close(ctx.tx_socket);
		}
		if(ctx.rx_socket >= 0)
		{
			lwip_close(ctx.rx_socket);
		}
		porting_test_call_tcpip(porting_test_teardown_on_tcpip, &ctx);
		return 1;
	}

	result = porting_test_run_roundtrip(&ctx);
	if(result != 0)
	{
		tprintf("porting-test[%s]: round-trip failed\n", test_case->name);
	}
	else
	{
		tprintf("porting-test[%s]: UDP round-trip passed, wire length=%u bytes\n",
		       test_case->name,
		       (unsigned int)ctx.wire_len);
	}

	lwip_close(ctx.tx_socket);
	lwip_close(ctx.rx_socket);
	porting_test_call_tcpip(porting_test_teardown_on_tcpip, &ctx);

	return result == 0 ? 0 : 1;
}

int porting_test_run(void)
{
	size_t index;
	int result;

	for(index = 0; index < (sizeof(porting_test_cases) / sizeof(porting_test_cases[0])); index++)
	{
		result = porting_test_run_case(&porting_test_cases[index]);
		if(result != 0)
		{
			return result;
		}
	}

	return 0;
}

#endif