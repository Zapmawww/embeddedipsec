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

#include <string.h>

#include "ipsec/aes_cbc.h"
#include "ipsec/ah.h"
#include "ipsec/debug.h"
#include "ipsec/esp.h"
#include "ipsec/ipsec.h"
#include "ipsec/sa.h"
#include "ipsec/util.h"
#include "testing/structural/structural_test.h"

#define TRANSPORT_TEST_HEADROOM         (128)
#define TRANSPORT_TEST_IPV4_PACKET_SIZE (IPSEC_IPV4_HDR_SIZE + sizeof(ipsec_tcp_header))
#define TRANSPORT_TEST_IPV6_PACKET_SIZE (IPSEC_IPV6_HDR_SIZE + sizeof(ipsec_tcp_header))

static const __u8 transport_test_mask_full[16] =
{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const __u8 transport_test_ipv6_src[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const __u8 transport_test_ipv6_dst[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x22, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20
};

static __u8 transport_test_esp_padding(int len, __u8 block_len)
{
	int padding;

	for(padding = 0; padding < block_len; padding++)
	{
		if(((len + padding) % block_len) == 0)
		{
			return (__u8)padding;
		}
	}

	return 0;
}

static void transport_test_reset_replay(sad_entry *sa)
{
	ipsec_sad_reset_replay(sa);
}

static void transport_test_init_ipv4_tcp_packet(unsigned char *buffer, __u32 src, __u32 dst, __u16 src_port, __u16 dst_port)
{
	ipsec_ip_header *ip;
	ipsec_tcp_header *tcp;

	memset(buffer, 0, TRANSPORT_TEST_IPV4_PACKET_SIZE);
	ip = (ipsec_ip_header *)buffer;
	tcp = (ipsec_tcp_header *)(buffer + IPSEC_IPV4_HDR_SIZE);

	ip->v_hl = 0x45;
	ip->tos = 0;
	ip->len = ipsec_htons(TRANSPORT_TEST_IPV4_PACKET_SIZE);
	ip->id = ipsec_htons(0x1234);
	ip->offset = 0;
	ip->ttl = 64;
	ip->protocol = IPSEC_PROTO_TCP;
	ip->src = src;
	ip->dest = dst;
	ip->chksum = 0;
	ip->chksum = ipsec_ip_chksum(ip, IPSEC_IPV4_HDR_SIZE);

	tcp->src = ipsec_htons(src_port);
	tcp->dest = ipsec_htons(dst_port);
	tcp->offset_flags = ipsec_htons(0x5000);
	tcp->wnd = ipsec_htons(1024);
}

static void transport_test_init_ipv6_tcp_packet(unsigned char *buffer, const __u8 *src, const __u8 *dst, __u16 src_port, __u16 dst_port)
{
	ipsec_ipv6_header *ip6;
	ipsec_tcp_header *tcp;

	memset(buffer, 0, TRANSPORT_TEST_IPV6_PACKET_SIZE);
	ip6 = (ipsec_ipv6_header *)buffer;
	tcp = (ipsec_tcp_header *)(buffer + IPSEC_IPV6_HDR_SIZE);

	ip6->v_tc_fl = ipsec_htonl(6UL << 28);
	ip6->payload_len = ipsec_htons((__u16)sizeof(ipsec_tcp_header));
	ip6->nexthdr = IPSEC_PROTO_TCP;
	ip6->hop_limit = 64;
	memcpy(ip6->src, src, 16);
	memcpy(ip6->dest, dst, 16);

	tcp->src = ipsec_htons(src_port);
	tcp->dest = ipsec_htons(dst_port);
	tcp->offset_flags = ipsec_htons(0x5000);
	tcp->wnd = ipsec_htons(1024);
}

static sad_entry transport_test_make_ipv4_ah_sa(void)
{
	return (sad_entry){ SAD_ENTRY(192,168,1,20, 255,255,255,255,
						  0x3301,
						  IPSEC_PROTO_AH, IPSEC_TRANSPORT,
						  0,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  IPSEC_HMAC_MD5,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0, 0, 0, 0) };
}

static sad_entry transport_test_make_ipv4_esp_sa(void)
{
	return (sad_entry){ SAD_ENTRY(192,168,1,20, 255,255,255,255,
						  0x3302,
						  IPSEC_PROTO_ESP, IPSEC_TRANSPORT,
						  IPSEC_AES_CBC,
						  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
						  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0,
						  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						  0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };
}

static sad_entry transport_test_make_ipv6_ah_sa(void)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 0,0,0,0,
						  0x3401,
						  IPSEC_PROTO_AH, IPSEC_TRANSPORT,
						  0,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  IPSEC_HMAC_MD5,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0, 0, 0, 0) };

	ipsec_sad_set_ipv6(&sa, transport_test_ipv6_dst, transport_test_mask_full);
	return sa;
}

static sad_entry transport_test_make_ipv6_esp_sa(void)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 0,0,0,0,
						  0x3402,
						  IPSEC_PROTO_ESP, IPSEC_TRANSPORT,
						  IPSEC_AES_CBC,
						  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
						  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0,
						  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						  0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };

	ipsec_sad_set_ipv6(&sa, transport_test_ipv6_dst, transport_test_mask_full);
	return sa;
}

static int transport_test_ipv4_ah(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	unsigned char original[TRANSPORT_TEST_IPV4_PACKET_SIZE];
	unsigned char buffer[TRANSPORT_TEST_HEADROOM + TRANSPORT_TEST_IPV4_PACKET_SIZE + 64];
	unsigned char *packet;
	spd_entry outbound_spd;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	spd_entry *inbound_spd;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
	sad_entry *inbound_sa;
	db_set_netif *databases;

	local_error_count = 0;
	enc_offset = 0;
	enc_len = 0;
	dec_offset = 0;
	dec_len = 0;
	memset(buffer, 0, sizeof(buffer));
	memset(&outbound_spd, 0, sizeof(outbound_spd));
	memset(inbound_spd_data, 0, sizeof(inbound_spd_data));
	memset(outbound_spd_data, 0, sizeof(outbound_spd_data));
	memset(inbound_sad_data, 0, sizeof(inbound_sad_data));
	memset(outbound_sad_data, 0, sizeof(outbound_sad_data));

	transport_test_init_ipv4_tcp_packet(original, ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("192.168.1.20"), 1234, 4321);
	packet = buffer + TRANSPORT_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));
	outbound_sa = transport_test_make_ipv4_ah_sa();
	inbound_sa_template = transport_test_make_ipv4_ah_sa();
	transport_test_reset_replay(&outbound_sa);
	transport_test_reset_replay(&inbound_sa_template);
	inbound_sa_template.sequence_number = 0;
	outbound_spd = (spd_entry){ SPD_ENTRY(192,168,1,10, 255,255,255,255, 192,168,1,20, 255,255,255,255, IPSEC_PROTO_TCP, 1234, 4321, POLICY_APPLY, 0) };
	ipsec_spd_add_sa(&outbound_spd, &outbound_sa);

	databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(databases == NULL)
	{
		return 1;
	}

	inbound_sa = ipsec_sad_add(&inbound_sa_template, &databases->inbound_sad);
	inbound_spd = ipsec_spd_add(ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("255.255.255.255"),
					   ipsec_inet_addr("192.168.1.20"), ipsec_inet_addr("255.255.255.255"),
					   IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY,
					   &databases->inbound_spd);
	if((inbound_sa == NULL) || (inbound_spd == NULL))
	{
		ipsec_spd_release_dbs(databases);
		return 1;
	}
	ipsec_spd_add_sa(inbound_spd, inbound_sa);

	ret_val = ipsec_output(packet, (int)(sizeof(buffer) - TRANSPORT_TEST_HEADROOM), &enc_offset, &enc_len,
				      ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("192.168.1.20"), &outbound_spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_ah", "FAILURE", ("ipsec_output() failed for IPv4 AH transport"));
		ipsec_spd_release_dbs(databases);
		return local_error_count;
	}

	if((enc_offset != 0) || (enc_len != (TRANSPORT_TEST_IPV4_PACKET_SIZE + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV)))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_ah", "FAILURE", ("IPv4 AH transport encapsulation returned unexpected offset or length"));
	}

	if((ipsec_packet_family(packet) != IPSEC_AF_INET) || (ipsec_packet_protocol(packet) != IPSEC_PROTO_AH))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_ah", "FAILURE", ("IPv4 AH transport encapsulation did not update the IP protocol as expected"));
	}

	ret_val = ipsec_input(packet, enc_len, &dec_offset, &dec_len, databases);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_ah", "FAILURE", ("ipsec_input() failed for IPv4 AH transport"));
	}

	if((dec_offset != 0) || (dec_len != TRANSPORT_TEST_IPV4_PACKET_SIZE) || (memcmp(packet, original, TRANSPORT_TEST_IPV4_PACKET_SIZE) != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_ah", "FAILURE", ("IPv4 AH transport roundtrip did not recover the original packet"));
	}

	ipsec_spd_release_dbs(databases);
	return local_error_count;
}

static int transport_test_ipv4_esp(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	__u8 padding;
	unsigned char original[TRANSPORT_TEST_IPV4_PACKET_SIZE];
	unsigned char buffer[TRANSPORT_TEST_HEADROOM + TRANSPORT_TEST_IPV4_PACKET_SIZE + 64];
	unsigned char *packet;
	spd_entry outbound_spd;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	spd_entry *inbound_spd;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
	sad_entry *inbound_sa;
	db_set_netif *databases;

	local_error_count = 0;
	enc_offset = 0;
	enc_len = 0;
	dec_offset = 0;
	dec_len = 0;
	memset(buffer, 0, sizeof(buffer));
	memset(&outbound_spd, 0, sizeof(outbound_spd));
	memset(inbound_spd_data, 0, sizeof(inbound_spd_data));
	memset(outbound_spd_data, 0, sizeof(outbound_spd_data));
	memset(inbound_sad_data, 0, sizeof(inbound_sad_data));
	memset(outbound_sad_data, 0, sizeof(outbound_sad_data));

	transport_test_init_ipv4_tcp_packet(original, ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("192.168.1.20"), 2222, 3333);
	packet = buffer + TRANSPORT_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));
	padding = transport_test_esp_padding((int)sizeof(ipsec_tcp_header) + 2, IPSEC_AES_CBC_BLOCK_SIZE);

	outbound_sa = transport_test_make_ipv4_esp_sa();
	inbound_sa_template = transport_test_make_ipv4_esp_sa();
	transport_test_reset_replay(&outbound_sa);
	transport_test_reset_replay(&inbound_sa_template);
	inbound_sa_template.sequence_number = 0;
	outbound_spd = (spd_entry){ SPD_ENTRY(192,168,1,10, 255,255,255,255, 192,168,1,20, 255,255,255,255, IPSEC_PROTO_TCP, 2222, 3333, POLICY_APPLY, 0) };
	ipsec_spd_add_sa(&outbound_spd, &outbound_sa);

	databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(databases == NULL)
	{
		return 1;
	}

	inbound_sa = ipsec_sad_add(&inbound_sa_template, &databases->inbound_sad);
	inbound_spd = ipsec_spd_add(ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("255.255.255.255"),
					   ipsec_inet_addr("192.168.1.20"), ipsec_inet_addr("255.255.255.255"),
					   IPSEC_PROTO_TCP, ipsec_htons(2222), ipsec_htons(3333), POLICY_APPLY,
					   &databases->inbound_spd);
	if((inbound_sa == NULL) || (inbound_spd == NULL))
	{
		ipsec_spd_release_dbs(databases);
		return 1;
	}
	ipsec_spd_add_sa(inbound_spd, inbound_sa);

	ret_val = ipsec_output(packet, (int)(sizeof(buffer) - TRANSPORT_TEST_HEADROOM), &enc_offset, &enc_len,
				      ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("192.168.1.20"), &outbound_spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_esp", "FAILURE", ("ipsec_output() failed for IPv4 ESP transport"));
		ipsec_spd_release_dbs(databases);
		return local_error_count;
	}

	if((enc_offset != 0) || (enc_len != (TRANSPORT_TEST_IPV4_PACKET_SIZE + IPSEC_ESP_HDR_SIZE + IPSEC_ESP_AES_CBC_IV_SIZE + padding + 2)))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_esp", "FAILURE", ("IPv4 ESP transport encapsulation returned unexpected offset or length"));
	}

	if((ipsec_packet_family(packet) != IPSEC_AF_INET) || (ipsec_packet_protocol(packet) != IPSEC_PROTO_ESP))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_esp", "FAILURE", ("IPv4 ESP transport encapsulation did not update the IP protocol as expected"));
	}

	ret_val = ipsec_input(packet, enc_len, &dec_offset, &dec_len, databases);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_esp", "FAILURE", ("ipsec_input() failed for IPv4 ESP transport"));
	}

	if((dec_offset != 0) || (dec_len != TRANSPORT_TEST_IPV4_PACKET_SIZE) || (memcmp(packet, original, TRANSPORT_TEST_IPV4_PACKET_SIZE) != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv4_esp", "FAILURE", ("IPv4 ESP transport roundtrip did not recover the original packet"));
	}

	ipsec_spd_release_dbs(databases);
	return local_error_count;
}

static int transport_test_ipv6_ah(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	unsigned char original[TRANSPORT_TEST_IPV6_PACKET_SIZE];
	unsigned char buffer[TRANSPORT_TEST_HEADROOM + TRANSPORT_TEST_IPV6_PACKET_SIZE + 64];
	unsigned char *packet;
	spd_entry outbound_spd;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	spd_entry *inbound_spd;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
	sad_entry *inbound_sa;
	db_set_netif *databases;

	local_error_count = 0;
	enc_offset = 0;
	enc_len = 0;
	dec_offset = 0;
	dec_len = 0;
	memset(buffer, 0, sizeof(buffer));
	memset(&outbound_spd, 0, sizeof(outbound_spd));
	memset(inbound_spd_data, 0, sizeof(inbound_spd_data));
	memset(outbound_spd_data, 0, sizeof(outbound_spd_data));
	memset(inbound_sad_data, 0, sizeof(inbound_sad_data));
	memset(outbound_sad_data, 0, sizeof(outbound_sad_data));

	transport_test_init_ipv6_tcp_packet(original, transport_test_ipv6_src, transport_test_ipv6_dst, 1234, 4321);
	packet = buffer + TRANSPORT_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));
	outbound_sa = transport_test_make_ipv6_ah_sa();
	inbound_sa_template = transport_test_make_ipv6_ah_sa();
	transport_test_reset_replay(&outbound_sa);
	transport_test_reset_replay(&inbound_sa_template);
	inbound_sa_template.sequence_number = 0;
	ipsec_spd_set_ipv6(&outbound_spd, transport_test_ipv6_src, transport_test_mask_full, transport_test_ipv6_dst, transport_test_mask_full);
	outbound_spd.protocol = IPSEC_PROTO_TCP;
	outbound_spd.src_port = ipsec_htons(1234);
	outbound_spd.dest_port = ipsec_htons(4321);
	outbound_spd.policy = POLICY_APPLY;
	outbound_spd.use_flag = IPSEC_USED;
	ipsec_spd_add_sa(&outbound_spd, &outbound_sa);

	databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(databases == NULL)
	{
		return 1;
	}

	inbound_sa = ipsec_sad_add(&inbound_sa_template, &databases->inbound_sad);
	inbound_spd = ipsec_spd_add_ipv6(transport_test_ipv6_src, transport_test_mask_full,
						transport_test_ipv6_dst, transport_test_mask_full,
						IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY,
						&databases->inbound_spd);
	if((inbound_sa == NULL) || (inbound_spd == NULL))
	{
		ipsec_spd_release_dbs(databases);
		return 1;
	}
	ipsec_spd_add_sa(inbound_spd, inbound_sa);

	ret_val = ipsec_output_ipv6(packet, (int)(sizeof(buffer) - TRANSPORT_TEST_HEADROOM), &enc_offset, &enc_len,
					 transport_test_ipv6_src, transport_test_ipv6_dst, &outbound_spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_ah", "FAILURE", ("ipsec_output_ipv6() failed for IPv6 AH transport"));
		ipsec_spd_release_dbs(databases);
		return local_error_count;
	}

	if((enc_offset != 0) || (enc_len != (TRANSPORT_TEST_IPV6_PACKET_SIZE + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV)))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_ah", "FAILURE", ("IPv6 AH transport encapsulation returned unexpected offset or length"));
	}

	if((ipsec_packet_family(packet) != IPSEC_AF_INET6) || (ipsec_packet_protocol(packet) != IPSEC_PROTO_AH))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_ah", "FAILURE", ("IPv6 AH transport encapsulation did not update the next-header field as expected"));
	}

	ret_val = ipsec_input(packet, enc_len, &dec_offset, &dec_len, databases);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_ah", "FAILURE", ("ipsec_input() failed for IPv6 AH transport"));
	}

	if((dec_offset != 0) || (dec_len != TRANSPORT_TEST_IPV6_PACKET_SIZE) || (memcmp(packet, original, TRANSPORT_TEST_IPV6_PACKET_SIZE) != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_ah", "FAILURE", ("IPv6 AH transport roundtrip did not recover the original packet"));
	}

	ipsec_spd_release_dbs(databases);
	return local_error_count;
}

static int transport_test_ipv6_esp(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	__u8 padding;
	unsigned char original[TRANSPORT_TEST_IPV6_PACKET_SIZE];
	unsigned char buffer[TRANSPORT_TEST_HEADROOM + TRANSPORT_TEST_IPV6_PACKET_SIZE + 64];
	unsigned char *packet;
	spd_entry outbound_spd;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	spd_entry *inbound_spd;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
	sad_entry *inbound_sa;
	db_set_netif *databases;

	local_error_count = 0;
	enc_offset = 0;
	enc_len = 0;
	dec_offset = 0;
	dec_len = 0;
	memset(buffer, 0, sizeof(buffer));
	memset(&outbound_spd, 0, sizeof(outbound_spd));
	memset(inbound_spd_data, 0, sizeof(inbound_spd_data));
	memset(outbound_spd_data, 0, sizeof(outbound_spd_data));
	memset(inbound_sad_data, 0, sizeof(inbound_sad_data));
	memset(outbound_sad_data, 0, sizeof(outbound_sad_data));

	transport_test_init_ipv6_tcp_packet(original, transport_test_ipv6_src, transport_test_ipv6_dst, 2222, 3333);
	packet = buffer + TRANSPORT_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));
	padding = transport_test_esp_padding((int)sizeof(ipsec_tcp_header) + 2, IPSEC_AES_CBC_BLOCK_SIZE);

	outbound_sa = transport_test_make_ipv6_esp_sa();
	inbound_sa_template = transport_test_make_ipv6_esp_sa();
	transport_test_reset_replay(&outbound_sa);
	transport_test_reset_replay(&inbound_sa_template);
	inbound_sa_template.sequence_number = 0;
	ipsec_spd_set_ipv6(&outbound_spd, transport_test_ipv6_src, transport_test_mask_full, transport_test_ipv6_dst, transport_test_mask_full);
	outbound_spd.protocol = IPSEC_PROTO_TCP;
	outbound_spd.src_port = ipsec_htons(2222);
	outbound_spd.dest_port = ipsec_htons(3333);
	outbound_spd.policy = POLICY_APPLY;
	outbound_spd.use_flag = IPSEC_USED;
	ipsec_spd_add_sa(&outbound_spd, &outbound_sa);

	databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(databases == NULL)
	{
		return 1;
	}

	inbound_sa = ipsec_sad_add(&inbound_sa_template, &databases->inbound_sad);
	inbound_spd = ipsec_spd_add_ipv6(transport_test_ipv6_src, transport_test_mask_full,
						transport_test_ipv6_dst, transport_test_mask_full,
						IPSEC_PROTO_TCP, ipsec_htons(2222), ipsec_htons(3333), POLICY_APPLY,
						&databases->inbound_spd);
	if((inbound_sa == NULL) || (inbound_spd == NULL))
	{
		ipsec_spd_release_dbs(databases);
		return 1;
	}
	ipsec_spd_add_sa(inbound_spd, inbound_sa);

	ret_val = ipsec_output_ipv6(packet, (int)(sizeof(buffer) - TRANSPORT_TEST_HEADROOM), &enc_offset, &enc_len,
					 transport_test_ipv6_src, transport_test_ipv6_dst, &outbound_spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_esp", "FAILURE", ("ipsec_output_ipv6() failed for IPv6 ESP transport"));
		ipsec_spd_release_dbs(databases);
		return local_error_count;
	}

	if((enc_offset != 0) || (enc_len != (TRANSPORT_TEST_IPV6_PACKET_SIZE + IPSEC_ESP_HDR_SIZE + IPSEC_ESP_AES_CBC_IV_SIZE + padding + 2)))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_esp", "FAILURE", ("IPv6 ESP transport encapsulation returned unexpected offset or length"));
	}

	if((ipsec_packet_family(packet) != IPSEC_AF_INET6) || (ipsec_packet_protocol(packet) != IPSEC_PROTO_ESP))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_esp", "FAILURE", ("IPv6 ESP transport encapsulation did not update the next-header field as expected"));
	}

	ret_val = ipsec_input(packet, enc_len, &dec_offset, &dec_len, databases);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_esp", "FAILURE", ("ipsec_input() failed for IPv6 ESP transport"));
	}

	if((dec_offset != 0) || (dec_len != TRANSPORT_TEST_IPV6_PACKET_SIZE) || (memcmp(packet, original, TRANSPORT_TEST_IPV6_PACKET_SIZE) != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("transport_test_ipv6_esp", "FAILURE", ("IPv6 ESP transport roundtrip did not recover the original packet"));
	}

	ipsec_spd_release_dbs(databases);
	return local_error_count;
}

void transport_test(test_result *global_results)
{
	test_result sub_results = {0, 0, 0, 0};
	int retcode;

	#if IPSEC_ENABLE_AH && IPSEC_ENABLE_TRANSPORT_MODE
	sub_results.tests += 4;
	sub_results.functions += 1;
	retcode = transport_test_ipv4_ah();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "transport_test_ipv4_ah()", (""));

	sub_results.tests += 4;
	sub_results.functions += 1;
	retcode = transport_test_ipv6_ah();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "transport_test_ipv6_ah()", (""));
	#endif

	#if IPSEC_ENABLE_ESP && IPSEC_ENABLE_TRANSPORT_MODE
	sub_results.tests += 4;
	sub_results.functions += 1;
	retcode = transport_test_ipv4_esp();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "transport_test_ipv4_esp()", (""));

	sub_results.tests += 4;
	sub_results.functions += 1;
	retcode = transport_test_ipv6_esp();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "transport_test_ipv6_esp()", (""));
	#endif

	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}