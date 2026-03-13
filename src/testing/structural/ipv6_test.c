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

#include <string.h>

#include "ipsec/ah.h"
#include "ipsec/debug.h"
#include "ipsec/esp.h"
#include "ipsec/ipsec.h"
#include "ipsec/sa.h"
#include "ipsec/util.h"
#include "testing/structural/structural_test.h"

#define IPV6_TEST_PACKET_SIZE (IPSEC_IPV6_HDR_SIZE + sizeof(ipsec_tcp_header))
#define IPV6_TEST_HEADROOM    (128)

extern __u32 ipsec_ah_bitmap;
extern __u32 ipsec_ah_lastSeq;
extern __u32 ipsec_esp_bitmap;
extern __u32 ipsec_esp_lastSeq;

static const __u8 ipv6_test_mask_full[16] =
{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const __u8 ipv6_test_inner_src[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const __u8 ipv6_test_inner_dst[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20
};

static const __u8 ipv6_test_outer_src[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0xaa, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const __u8 ipv6_test_outer_dst[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0xbb, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

static sad_entry ipv6_test_make_ah_sa(void)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 0,0,0,0,
						  0x2201,
						  IPSEC_PROTO_AH, IPSEC_TUNNEL,
						  0,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  IPSEC_HMAC_MD5,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0, 0, 0, 0) };

	ipsec_sad_set_ipv6(&sa, ipv6_test_outer_dst, ipv6_test_mask_full);
	return sa;
}

static sad_entry ipv6_test_make_esp_sa(void)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 0,0,0,0,
						  0x2202,
						  IPSEC_PROTO_ESP, IPSEC_TUNNEL,
						  IPSEC_3DES,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
						  0,
						  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						  0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };

	ipsec_sad_set_ipv6(&sa, ipv6_test_outer_dst, ipv6_test_mask_full);
	return sa;
}

static void ipv6_test_init_tcp_packet(unsigned char *buffer, const __u8 *src, const __u8 *dst, __u16 src_port, __u16 dst_port)
{
	ipsec_ipv6_header *ip6;
	ipsec_tcp_header *tcp;

	memset(buffer, 0, IPV6_TEST_PACKET_SIZE);
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

static int ipv6_test_spd_sad_lookup(void)
{
	int local_error_count;
	spd_entry spd_entries[IPSEC_MAX_SPD_ENTRIES];
	sad_entry sad_entries[IPSEC_MAX_SAD_ENTRIES];
	spd_table spd_table;
	sad_table sad_table;
	spd_entry *spd;
	sad_entry *sad;
	ipsec_ip_address dest_addr;
	unsigned char packet[IPV6_TEST_PACKET_SIZE];
	sad_entry sa = ipv6_test_make_ah_sa();

	local_error_count = 0;
	memset(spd_entries, 0, sizeof(spd_entries));
	memset(sad_entries, 0, sizeof(sad_entries));
	memset(&spd_table, 0, sizeof(spd_table));
	memset(&sad_table, 0, sizeof(sad_table));

	spd_table.table = spd_entries;
	spd_table.size = IPSEC_MAX_SPD_ENTRIES;
	sad_table.table = sad_entries;

	sad = ipsec_sad_add(&sa, &sad_table);
	if(sad == NULL)
	{
		return 1;
	}

	spd = ipsec_spd_add_ipv6(ipv6_test_inner_src, ipv6_test_mask_full,
							 ipv6_test_inner_dst, ipv6_test_mask_full,
							 IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY, &spd_table);
	if(spd == NULL)
	{
		return 1;
	}
	ipsec_spd_add_sa(spd, sad);

	ipv6_test_init_tcp_packet(packet, ipv6_test_inner_src, ipv6_test_inner_dst, 1234, 4321);

	if(ipsec_spd_lookup(packet, &spd_table) != spd)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_spd_sad_lookup", "FAILURE", ("IPv6 SPD lookup did not return the expected entry"));
	}

	ipsec_address_set_ipv6(&dest_addr, ipv6_test_outer_dst);
	if(ipsec_sad_lookup_addr(&dest_addr, IPSEC_PROTO_AH, sa.spi, &sad_table) != sad)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_spd_sad_lookup", "FAILURE", ("IPv6 SAD lookup did not return the expected entry"));
	}

	return local_error_count;
}

static int ipv6_test_ah_roundtrip(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	unsigned char original[IPV6_TEST_PACKET_SIZE];
	unsigned char buffer[IPV6_TEST_HEADROOM + IPV6_TEST_PACKET_SIZE + 64];
	unsigned char *packet;
	unsigned char *outer_packet;
	spd_entry spd = { SPD_ENTRY(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, IPSEC_PROTO_TCP, 1234, 4321, POLICY_APPLY, 0) };
	sad_entry sa = ipv6_test_make_ah_sa();

	local_error_count = 0;
	enc_offset = 0;
	enc_len = 0;
	dec_offset = 0;
	dec_len = 0;
	memset(buffer, 0, sizeof(buffer));
	ipv6_test_init_tcp_packet(original, ipv6_test_inner_src, ipv6_test_inner_dst, 1234, 4321);
	packet = buffer + IPV6_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));
	ipsec_ah_bitmap = 0;
	ipsec_ah_lastSeq = 0;

	ipsec_spd_set_ipv6(&spd, ipv6_test_inner_src, ipv6_test_mask_full, ipv6_test_inner_dst, ipv6_test_mask_full);
	ipsec_spd_add_sa(&spd, &sa);

	ret_val = ipsec_output_ipv6(packet, (int)(sizeof(buffer) - IPV6_TEST_HEADROOM), &enc_offset, &enc_len,
						    ipv6_test_outer_src, ipv6_test_outer_dst, &spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_ah_roundtrip", "FAILURE", ("ipsec_output_ipv6() failed for AH"));
		return local_error_count;
	}

	outer_packet = packet + enc_offset;
	if((enc_offset != -64) || (enc_len != (IPV6_TEST_PACKET_SIZE + 64)))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_ah_roundtrip", "FAILURE", ("AH IPv6 encapsulation returned unexpected offset or length"));
	}

	if((ipsec_packet_family(outer_packet) != IPSEC_AF_INET6) || (ipsec_packet_protocol(outer_packet) != IPSEC_PROTO_AH))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_ah_roundtrip", "FAILURE", ("AH IPv6 encapsulation did not create the expected outer header"));
	}

	ret_val = ipsec_ah_check(outer_packet, &dec_offset, &dec_len, &sa);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_ah_roundtrip", "FAILURE", ("ipsec_ah_check() failed for an encapsulated IPv6 packet"));
		return local_error_count;
	}

	if((dec_offset != 64) || (dec_len != IPV6_TEST_PACKET_SIZE))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_ah_roundtrip", "FAILURE", ("AH IPv6 decapsulation returned unexpected offset or length"));
	}

	if(memcmp(outer_packet + dec_offset, original, IPV6_TEST_PACKET_SIZE) != 0)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_ah_roundtrip", "FAILURE", ("AH IPv6 roundtrip did not preserve the inner packet"));
	}

	ipsec_ah_bitmap = 0;
	ipsec_ah_lastSeq = 0;

	return local_error_count;
}

static int ipv6_test_esp_roundtrip(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	unsigned char original[IPV6_TEST_PACKET_SIZE];
	unsigned char buffer[IPV6_TEST_HEADROOM + IPV6_TEST_PACKET_SIZE + 64];
	unsigned char *packet;
	unsigned char *outer_packet;
	sad_entry sa = ipv6_test_make_esp_sa();

	local_error_count = 0;
	enc_offset = 0;
	enc_len = 0;
	dec_offset = 0;
	dec_len = 0;
	memset(buffer, 0, sizeof(buffer));
	ipv6_test_init_tcp_packet(original, ipv6_test_inner_src, ipv6_test_inner_dst, 2222, 3333);
	packet = buffer + IPV6_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));
	ipsec_esp_bitmap = 0;
	ipsec_esp_lastSeq = 0;

	ret_val = ipsec_esp_encapsulate_ipv6(packet, &enc_offset, &enc_len, &sa, ipv6_test_outer_src, ipv6_test_outer_dst);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_esp_roundtrip", "FAILURE", ("ipsec_esp_encapsulate_ipv6() failed"));
		return local_error_count;
	}

	outer_packet = packet + enc_offset;
	if((enc_offset != -56) || (enc_len != 120))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_esp_roundtrip", "FAILURE", ("ESP IPv6 encapsulation returned unexpected offset or length"));
	}

	if((ipsec_packet_family(outer_packet) != IPSEC_AF_INET6) || (ipsec_packet_protocol(outer_packet) != IPSEC_PROTO_ESP))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_esp_roundtrip", "FAILURE", ("ESP IPv6 encapsulation did not create the expected outer header"));
	}

	ret_val = ipsec_esp_decapsulate(outer_packet, &dec_offset, &dec_len, &sa);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_esp_roundtrip", "FAILURE", ("ipsec_esp_decapsulate() failed for an encapsulated IPv6 packet"));
		return local_error_count;
	}

	if((dec_offset != 56) || (dec_len != IPV6_TEST_PACKET_SIZE))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_esp_roundtrip", "FAILURE", ("ESP IPv6 decapsulation returned unexpected offset or length"));
	}

	if(memcmp(outer_packet + dec_offset, original, IPV6_TEST_PACKET_SIZE) != 0)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_esp_roundtrip", "FAILURE", ("ESP IPv6 roundtrip did not preserve the inner packet"));
	}

	ipsec_esp_bitmap = 0;
	ipsec_esp_lastSeq = 0;

	return local_error_count;
}

static int ipv6_test_input_ah(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	unsigned char original[IPV6_TEST_PACKET_SIZE];
	unsigned char buffer[IPV6_TEST_HEADROOM + IPV6_TEST_PACKET_SIZE + 64];
	unsigned char *packet;
	unsigned char *outer_packet;
	spd_entry outbound_spd;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	spd_entry *inbound_spd;
	sad_entry inbound_sa_template;
	sad_entry outbound_sa;
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

	ipv6_test_init_tcp_packet(original, ipv6_test_inner_src, ipv6_test_inner_dst, 1234, 4321);
	packet = buffer + IPV6_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));

	ipsec_ah_bitmap = 0;
	ipsec_ah_lastSeq = 0;
	outbound_sa = ipv6_test_make_ah_sa();
	inbound_sa_template = ipv6_test_make_ah_sa();
	inbound_sa_template.sequence_number = 0;
	ipsec_spd_set_ipv6(&outbound_spd, ipv6_test_inner_src, ipv6_test_mask_full, ipv6_test_inner_dst, ipv6_test_mask_full);
	ipsec_spd_add_sa(&outbound_spd, &outbound_sa);

	databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(databases == NULL)
	{
		return 1;
	}

	inbound_sa = ipsec_sad_add(&inbound_sa_template, &databases->inbound_sad);
	inbound_spd = ipsec_spd_add_ipv6(ipv6_test_inner_src, ipv6_test_mask_full,
							ipv6_test_inner_dst, ipv6_test_mask_full,
							IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY,
							&databases->inbound_spd);
	if((inbound_sa == NULL) || (inbound_spd == NULL))
	{
		ipsec_spd_release_dbs(databases);
		return 1;
	}
	ipsec_spd_add_sa(inbound_spd, inbound_sa);

	ret_val = ipsec_output_ipv6(packet, (int)(sizeof(buffer) - IPV6_TEST_HEADROOM), &enc_offset, &enc_len,
						    ipv6_test_outer_src, ipv6_test_outer_dst, &outbound_spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_ah", "FAILURE", ("ipsec_output_ipv6() failed while preparing the inbound AH packet"));
		ipsec_spd_release_dbs(databases);
		return local_error_count;
	}

	outer_packet = packet + enc_offset;
	ret_val = ipsec_input(outer_packet, enc_len, &dec_offset, &dec_len, databases);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_ah", "FAILURE", ("ipsec_input() failed for an IPv6 AH packet"));
	}

	if((dec_offset != 64) || (dec_len != IPV6_TEST_PACKET_SIZE))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_ah", "FAILURE", ("IPv6 AH inbound processing returned unexpected offset or length"));
	}

	if(memcmp(outer_packet + dec_offset, original, IPV6_TEST_PACKET_SIZE) != 0)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_ah", "FAILURE", ("IPv6 AH inbound processing did not recover the original packet"));
	}

	ipsec_spd_release_dbs(databases);
	ipsec_ah_bitmap = 0;
	ipsec_ah_lastSeq = 0;
	return local_error_count;
}

static int ipv6_test_input_esp(void)
{
	int local_error_count;
	int enc_offset;
	int enc_len;
	int dec_offset;
	int dec_len;
	int ret_val;
	unsigned char original[IPV6_TEST_PACKET_SIZE];
	unsigned char buffer[IPV6_TEST_HEADROOM + IPV6_TEST_PACKET_SIZE + 64];
	unsigned char *packet;
	unsigned char *outer_packet;
	spd_entry outbound_spd;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	spd_entry *inbound_spd;
	sad_entry inbound_sa_template;
	sad_entry outbound_sa;
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

	ipv6_test_init_tcp_packet(original, ipv6_test_inner_src, ipv6_test_inner_dst, 2222, 3333);
	packet = buffer + IPV6_TEST_HEADROOM;
	memcpy(packet, original, sizeof(original));

	ipsec_esp_bitmap = 0;
	ipsec_esp_lastSeq = 0;
	outbound_sa = ipv6_test_make_esp_sa();
	inbound_sa_template = ipv6_test_make_esp_sa();
	inbound_sa_template.sequence_number = 0;
	ipsec_spd_set_ipv6(&outbound_spd, ipv6_test_inner_src, ipv6_test_mask_full, ipv6_test_inner_dst, ipv6_test_mask_full);
	ipsec_spd_add_sa(&outbound_spd, &outbound_sa);

	databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(databases == NULL)
	{
		return 1;
	}

	inbound_sa = ipsec_sad_add(&inbound_sa_template, &databases->inbound_sad);
	inbound_spd = ipsec_spd_add_ipv6(ipv6_test_inner_src, ipv6_test_mask_full,
							ipv6_test_inner_dst, ipv6_test_mask_full,
							IPSEC_PROTO_TCP, ipsec_htons(2222), ipsec_htons(3333), POLICY_APPLY,
							&databases->inbound_spd);
	if((inbound_sa == NULL) || (inbound_spd == NULL))
	{
		ipsec_spd_release_dbs(databases);
		return 1;
	}
	ipsec_spd_add_sa(inbound_spd, inbound_sa);

	ret_val = ipsec_output_ipv6(packet, (int)(sizeof(buffer) - IPV6_TEST_HEADROOM), &enc_offset, &enc_len,
						    ipv6_test_outer_src, ipv6_test_outer_dst, &outbound_spd);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_esp", "FAILURE", ("ipsec_output_ipv6() failed while preparing the inbound ESP packet"));
		ipsec_spd_release_dbs(databases);
		return local_error_count;
	}

	outer_packet = packet + enc_offset;
	ret_val = ipsec_input(outer_packet, enc_len, &dec_offset, &dec_len, databases);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_esp", "FAILURE", ("ipsec_input() failed for an IPv6 ESP packet"));
	}

	if((dec_offset != 56) || (dec_len != IPV6_TEST_PACKET_SIZE))
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_esp", "FAILURE", ("IPv6 ESP inbound processing returned unexpected offset or length"));
	}

	if(memcmp(outer_packet + dec_offset, original, IPV6_TEST_PACKET_SIZE) != 0)
	{
		local_error_count++;
		IPSEC_LOG_TST("ipv6_test_input_esp", "FAILURE", ("IPv6 ESP inbound processing did not recover the original packet"));
	}

	ipsec_spd_release_dbs(databases);
	ipsec_esp_bitmap = 0;
	ipsec_esp_lastSeq = 0;
	return local_error_count;
}

void ipv6_test(test_result *global_results)
{
	test_result sub_results = {0, 0, 0, 0};
	int retcode;

	sub_results.tests += 2;
	sub_results.functions += 1;
	retcode = ipv6_test_spd_sad_lookup();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ipv6_test_spd_sad_lookup()", (""));

	#if IPSEC_ENABLE_AH && IPSEC_ENABLE_TUNNEL_MODE
	sub_results.tests += 3;
	sub_results.functions += 1;
	retcode = ipv6_test_ah_roundtrip();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ipv6_test_ah_roundtrip()", (""));

	sub_results.tests += 2;
	sub_results.functions += 1;
	retcode = ipv6_test_input_ah();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ipv6_test_input_ah()", (""));
	#endif

	#if IPSEC_ENABLE_ESP && IPSEC_ENABLE_TUNNEL_MODE
	sub_results.tests += 2;
	sub_results.functions += 1;
	retcode = ipv6_test_esp_roundtrip();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ipv6_test_esp_roundtrip()", (""));

	sub_results.tests += 2;
	sub_results.functions += 1;
	retcode = ipv6_test_input_esp();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ipv6_test_input_esp()", (""));
	#endif

	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}