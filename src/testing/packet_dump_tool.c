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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipsec/ah.h"
#include "ipsec/debug.h"
#include "ipsec/esp.h"
#include "ipsec/ipsec.h"
#include "ipsec/sa.h"
#include "ipsec/util.h"

#define PACKET_DUMP_HEADROOM             (128)
#define PACKET_DUMP_TAILROOM             (96)
#define PACKET_DUMP_MAX_PACKET_SIZE      (PACKET_DUMP_HEADROOM + IPSEC_MTU + PACKET_DUMP_TAILROOM)
#define PACKET_DUMP_PCAP_MAGIC           (0xa1b2c3d4UL)
#define PACKET_DUMP_PCAP_VERSION_MAJOR   (2)
#define PACKET_DUMP_PCAP_VERSION_MINOR   (4)
#define PACKET_DUMP_PCAP_LINKTYPE_RAW    (101)

typedef struct packet_dump_pcap_header_struct
{
	__u32 magic;
	__u16 version_major;
	__u16 version_minor;
	__u32 thiszone;
	__u32 sigfigs;
	__u32 snaplen;
	__u32 network;
} packet_dump_pcap_header;

typedef struct packet_dump_pcap_record_header_struct
{
	__u32 ts_sec;
	__u32 ts_usec;
	__u32 incl_len;
	__u32 orig_len;
} packet_dump_pcap_record_header;

typedef struct packet_dump_case_struct
{
	const char *name;
	__u8 family;
	__u8 protocol;
	__u8 mode;
	int original_len;
	unsigned char original[IPSEC_MTU];
	spd_entry outbound_spd;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
	spd_entry inbound_spd_template;
	__u8 outer_src_ipv6[16];
	__u8 outer_dst_ipv6[16];
	__u32 outer_src_ipv4;
	__u32 outer_dst_ipv4;
} packet_dump_case;

static const __u8 packet_dump_mask_full[16] =
{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const __u8 packet_dump_ipv6_transport_src[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const __u8 packet_dump_ipv6_transport_dst[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x22, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20
};

static const __u8 packet_dump_ipv6_tunnel_src[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0xaa, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const __u8 packet_dump_ipv6_tunnel_dst[16] =
{
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0xbb, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

static __u8 packet_dump_esp_padding(int len, __u8 block_len)
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

static void packet_dump_init_ipv4_tcp_packet(unsigned char *buffer, __u32 src, __u32 dst, __u16 src_port, __u16 dst_port)
{
	ipsec_ip_header *ip;
	ipsec_tcp_header *tcp;

	memset(buffer, 0, IPSEC_IPV4_HDR_SIZE + (int)sizeof(ipsec_tcp_header));
	ip = (ipsec_ip_header *)buffer;
	tcp = (ipsec_tcp_header *)(buffer + IPSEC_IPV4_HDR_SIZE);

	ip->v_hl = 0x45;
	ip->tos = 0;
	ip->len = ipsec_htons(IPSEC_IPV4_HDR_SIZE + (__u16)sizeof(ipsec_tcp_header));
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

static void packet_dump_init_ipv6_tcp_packet(unsigned char *buffer, const __u8 *src, const __u8 *dst, __u16 src_port, __u16 dst_port)
{
	ipsec_ipv6_header *ip6;
	ipsec_tcp_header *tcp;

	memset(buffer, 0, IPSEC_IPV6_HDR_SIZE + (int)sizeof(ipsec_tcp_header));
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

static sad_entry packet_dump_make_ipv4_ah_sa(__u32 spi, __u8 mode, __u32 dest)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 255,255,255,255,
					  spi,
					  IPSEC_PROTO_AH, mode,
					  0,
					  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					  IPSEC_HMAC_MD5,
					  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					  0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					  0, 0, 0, 0) };

	sa.dest = dest;
	return sa;
}

static sad_entry packet_dump_make_ipv4_esp_sa(__u32 spi, __u8 mode, __u32 dest)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 255,255,255,255,
					  spi,
					  IPSEC_PROTO_ESP, mode,
					  IPSEC_AES_CBC,
					  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
					  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
					  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0,
					  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };

	sa.dest = dest;
	return sa;
}

static sad_entry packet_dump_make_ipv6_ah_sa(__u32 spi, __u8 mode, const __u8 *dest)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 0,0,0,0,
					   spi,
					   IPSEC_PROTO_AH, mode,
					   0,
					   0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					   0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					   0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					   IPSEC_HMAC_MD5,
					   0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					   0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
					   0, 0, 0, 0) };

	ipsec_sad_set_ipv6(&sa, dest, packet_dump_mask_full);
	return sa;
}

static sad_entry packet_dump_make_ipv6_esp_sa(__u32 spi, __u8 mode, const __u8 *dest)
{
	sad_entry sa = { SAD_ENTRY(0,0,0,0, 0,0,0,0,
					   spi,
					   IPSEC_PROTO_ESP, mode,
					   IPSEC_AES_CBC,
					   0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
					   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0,
					   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0, 0, 0) };

	ipsec_sad_set_ipv6(&sa, dest, packet_dump_mask_full);
	return sa;
}

static void packet_dump_init_case(packet_dump_case *test_case, const char *name, __u8 family, __u8 protocol, __u8 mode)
{
	memset(test_case, 0, sizeof(*test_case));
	test_case->name = name;
	test_case->family = family;
	test_case->protocol = protocol;
	test_case->mode = mode;
	if(protocol == IPSEC_PROTO_AH)
	{
		test_case->inbound_sa_template.replay_win = IPSEC_SEQ_MAX_WINDOW;
	}
	else
	{
		test_case->inbound_sa_template.replay_win = IPSEC_SEQ_MAX_WINDOW;
	}
}

static void packet_dump_prepare_cases(packet_dump_case *cases, size_t *case_count)
{
	packet_dump_case *test_case;

	*case_count = 4;

	test_case = &cases[0];
	packet_dump_init_case(test_case, "ipv4-ah-transport", IPSEC_AF_INET, IPSEC_PROTO_AH, IPSEC_TRANSPORT);
	test_case->outer_src_ipv4 = ipsec_inet_addr("192.168.1.10");
	test_case->outer_dst_ipv4 = ipsec_inet_addr("192.168.1.20");
	packet_dump_init_ipv4_tcp_packet(test_case->original, test_case->outer_src_ipv4, test_case->outer_dst_ipv4, 1234, 4321);
	test_case->original_len = IPSEC_IPV4_HDR_SIZE + (int)sizeof(ipsec_tcp_header);
	test_case->outbound_sa = packet_dump_make_ipv4_ah_sa(0x5101, IPSEC_TRANSPORT, test_case->outer_dst_ipv4);
	test_case->inbound_sa_template = packet_dump_make_ipv4_ah_sa(0x5101, IPSEC_TRANSPORT, test_case->outer_dst_ipv4);
	test_case->outbound_spd = (spd_entry){ SPD_ENTRY(192,168,1,10, 255,255,255,255, 192,168,1,20, 255,255,255,255, IPSEC_PROTO_TCP, 1234, 4321, POLICY_APPLY, 0) };
	test_case->inbound_spd_template = (spd_entry){ SPD_ENTRY(192,168,1,10, 255,255,255,255, 192,168,1,20, 255,255,255,255, IPSEC_PROTO_TCP, 1234, 4321, POLICY_APPLY, 0) };

	test_case = &cases[1];
	packet_dump_init_case(test_case, "ipv4-esp-transport", IPSEC_AF_INET, IPSEC_PROTO_ESP, IPSEC_TRANSPORT);
	test_case->outer_src_ipv4 = ipsec_inet_addr("192.168.1.10");
	test_case->outer_dst_ipv4 = ipsec_inet_addr("192.168.1.20");
	packet_dump_init_ipv4_tcp_packet(test_case->original, test_case->outer_src_ipv4, test_case->outer_dst_ipv4, 2222, 3333);
	test_case->original_len = IPSEC_IPV4_HDR_SIZE + (int)sizeof(ipsec_tcp_header);
	test_case->outbound_sa = packet_dump_make_ipv4_esp_sa(0x5102, IPSEC_TRANSPORT, test_case->outer_dst_ipv4);
	test_case->inbound_sa_template = packet_dump_make_ipv4_esp_sa(0x5102, IPSEC_TRANSPORT, test_case->outer_dst_ipv4);
	test_case->outbound_spd = (spd_entry){ SPD_ENTRY(192,168,1,10, 255,255,255,255, 192,168,1,20, 255,255,255,255, IPSEC_PROTO_TCP, 2222, 3333, POLICY_APPLY, 0) };
	test_case->inbound_spd_template = (spd_entry){ SPD_ENTRY(192,168,1,10, 255,255,255,255, 192,168,1,20, 255,255,255,255, IPSEC_PROTO_TCP, 2222, 3333, POLICY_APPLY, 0) };

	test_case = &cases[2];
	packet_dump_init_case(test_case, "ipv6-ah-tunnel", IPSEC_AF_INET6, IPSEC_PROTO_AH, IPSEC_TUNNEL);
	memcpy(test_case->outer_src_ipv6, packet_dump_ipv6_tunnel_src, sizeof(test_case->outer_src_ipv6));
	memcpy(test_case->outer_dst_ipv6, packet_dump_ipv6_tunnel_dst, sizeof(test_case->outer_dst_ipv6));
	packet_dump_init_ipv6_tcp_packet(test_case->original, packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst, 4444, 5555);
	test_case->original_len = IPSEC_IPV6_HDR_SIZE + (int)sizeof(ipsec_tcp_header);
	test_case->outbound_sa = packet_dump_make_ipv6_ah_sa(0x5201, IPSEC_TUNNEL, test_case->outer_dst_ipv6);
	test_case->inbound_sa_template = packet_dump_make_ipv6_ah_sa(0x5201, IPSEC_TUNNEL, test_case->outer_dst_ipv6);
	ipsec_spd_set_ipv6(&test_case->outbound_spd, packet_dump_ipv6_transport_src, packet_dump_mask_full, packet_dump_ipv6_transport_dst, packet_dump_mask_full);
	test_case->outbound_spd.protocol = IPSEC_PROTO_TCP;
	test_case->outbound_spd.src_port = ipsec_htons(4444);
	test_case->outbound_spd.dest_port = ipsec_htons(5555);
	test_case->outbound_spd.policy = POLICY_APPLY;
	test_case->outbound_spd.use_flag = IPSEC_USED;
	ipsec_spd_set_ipv6(&test_case->inbound_spd_template, packet_dump_ipv6_transport_src, packet_dump_mask_full, packet_dump_ipv6_transport_dst, packet_dump_mask_full);
	test_case->inbound_spd_template.protocol = IPSEC_PROTO_TCP;
	test_case->inbound_spd_template.src_port = ipsec_htons(4444);
	test_case->inbound_spd_template.dest_port = ipsec_htons(5555);
	test_case->inbound_spd_template.policy = POLICY_APPLY;
	test_case->inbound_spd_template.use_flag = IPSEC_USED;

	test_case = &cases[3];
	packet_dump_init_case(test_case, "ipv6-esp-tunnel", IPSEC_AF_INET6, IPSEC_PROTO_ESP, IPSEC_TUNNEL);
	memcpy(test_case->outer_src_ipv6, packet_dump_ipv6_tunnel_src, sizeof(test_case->outer_src_ipv6));
	memcpy(test_case->outer_dst_ipv6, packet_dump_ipv6_tunnel_dst, sizeof(test_case->outer_dst_ipv6));
	packet_dump_init_ipv6_tcp_packet(test_case->original, packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst, 6666, 7777);
	test_case->original_len = IPSEC_IPV6_HDR_SIZE + (int)sizeof(ipsec_tcp_header);
	test_case->outbound_sa = packet_dump_make_ipv6_esp_sa(0x5202, IPSEC_TUNNEL, test_case->outer_dst_ipv6);
	test_case->inbound_sa_template = packet_dump_make_ipv6_esp_sa(0x5202, IPSEC_TUNNEL, test_case->outer_dst_ipv6);
	ipsec_spd_set_ipv6(&test_case->outbound_spd, packet_dump_ipv6_transport_src, packet_dump_mask_full, packet_dump_ipv6_transport_dst, packet_dump_mask_full);
	test_case->outbound_spd.protocol = IPSEC_PROTO_TCP;
	test_case->outbound_spd.src_port = ipsec_htons(6666);
	test_case->outbound_spd.dest_port = ipsec_htons(7777);
	test_case->outbound_spd.policy = POLICY_APPLY;
	test_case->outbound_spd.use_flag = IPSEC_USED;
	ipsec_spd_set_ipv6(&test_case->inbound_spd_template, packet_dump_ipv6_transport_src, packet_dump_mask_full, packet_dump_ipv6_transport_dst, packet_dump_mask_full);
	test_case->inbound_spd_template.protocol = IPSEC_PROTO_TCP;
	test_case->inbound_spd_template.src_port = ipsec_htons(6666);
	test_case->inbound_spd_template.dest_port = ipsec_htons(7777);
	test_case->inbound_spd_template.policy = POLICY_APPLY;
	test_case->inbound_spd_template.use_flag = IPSEC_USED;

	for(test_case = cases; test_case < cases + *case_count; ++test_case)
	{
		ipsec_sad_reset_replay(&test_case->outbound_sa);
		ipsec_sad_reset_replay(&test_case->inbound_sa_template);
		test_case->inbound_sa_template.sequence_number = 0;
		ipsec_spd_add_sa(&test_case->outbound_spd, &test_case->outbound_sa);
	}
}

static int packet_dump_write_pcap_header(FILE *stream)
{
	packet_dump_pcap_header header;

	header.magic = PACKET_DUMP_PCAP_MAGIC;
	header.version_major = PACKET_DUMP_PCAP_VERSION_MAJOR;
	header.version_minor = PACKET_DUMP_PCAP_VERSION_MINOR;
	header.thiszone = 0;
	header.sigfigs = 0;
	header.snaplen = 65535;
	header.network = PACKET_DUMP_PCAP_LINKTYPE_RAW;

	return fwrite(&header, sizeof(header), 1, stream) == 1 ? 0 : 1;
}

static int packet_dump_write_record(FILE *stream, const unsigned char *packet, int packet_len, __u32 index)
{
	packet_dump_pcap_record_header header;

	header.ts_sec = index;
	header.ts_usec = 0;
	header.incl_len = (__u32)packet_len;
	header.orig_len = (__u32)packet_len;

	if(fwrite(&header, sizeof(header), 1, stream) != 1)
	{
		return 1;
	}

	return fwrite(packet, (size_t)packet_len, 1, stream) == 1 ? 0 : 1;
}

static int packet_dump_generate(const char *path)
{
	packet_dump_case cases[4];
	size_t case_count;
	FILE *stream;
	size_t index;

	packet_dump_prepare_cases(cases, &case_count);
	stream = fopen(path, "wb");
	if(stream == NULL)
	{
		fprintf(stderr, "failed to open output file: %s\n", path);
		return 1;
	}

	if(packet_dump_write_pcap_header(stream) != 0)
	{
		fprintf(stderr, "failed to write PCAP header\n");
		fclose(stream);
		return 1;
	}

	for(index = 0; index < case_count; index++)
	{
		unsigned char packet_buffer[PACKET_DUMP_MAX_PACKET_SIZE];
		unsigned char *packet;
		int payload_offset;
		int payload_len;
		int status;
		packet_dump_case *test_case;

		test_case = &cases[index];
		memset(packet_buffer, 0, sizeof(packet_buffer));
		packet = packet_buffer + PACKET_DUMP_HEADROOM;
		memcpy(packet, test_case->original, (size_t)test_case->original_len);
		payload_offset = 0;
		payload_len = 0;

		if(test_case->family == IPSEC_AF_INET6)
		{
			status = ipsec_output_ipv6(packet, (int)(sizeof(packet_buffer) - PACKET_DUMP_HEADROOM), &payload_offset, &payload_len,
						   test_case->outer_src_ipv6, test_case->outer_dst_ipv6, &test_case->outbound_spd);
		}
		else
		{
			status = ipsec_output(packet, (int)(sizeof(packet_buffer) - PACKET_DUMP_HEADROOM), &payload_offset, &payload_len,
					      test_case->outer_src_ipv4, test_case->outer_dst_ipv4, &test_case->outbound_spd);
		}

		if(status != IPSEC_STATUS_SUCCESS)
		{
			fprintf(stderr, "generation failed for %s: %d\n", test_case->name, status);
			fclose(stream);
			return 1;
		}

		if(packet_dump_write_record(stream, packet + payload_offset, payload_len, (__u32)index + 1) != 0)
		{
			fprintf(stderr, "failed to write packet %s\n", test_case->name);
			fclose(stream);
			return 1;
		}

		printf("wrote %s (%d bytes)\n", test_case->name, payload_len);
	}

	fclose(stream);
	return 0;
}

static int packet_dump_prepare_verify_db(const packet_dump_case *cases, size_t case_count,
						 spd_entry *inbound_spd_data, spd_entry *outbound_spd_data,
						 sad_entry *inbound_sad_data, sad_entry *outbound_sad_data,
						 db_set_netif **databases)
{
	size_t index;

	memset(inbound_spd_data, 0, sizeof(spd_entry) * IPSEC_MAX_SPD_ENTRIES);
	memset(outbound_spd_data, 0, sizeof(spd_entry) * IPSEC_MAX_SPD_ENTRIES);
	memset(inbound_sad_data, 0, sizeof(sad_entry) * IPSEC_MAX_SAD_ENTRIES);
	memset(outbound_sad_data, 0, sizeof(sad_entry) * IPSEC_MAX_SAD_ENTRIES);

	*databases = ipsec_spd_load_dbs(inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data);
	if(*databases == NULL)
	{
		return 1;
	}

	for(index = 0; index < case_count; index++)
	{
		sad_entry *inbound_sa;
		spd_entry *inbound_spd;
		const packet_dump_case *test_case;

		test_case = &cases[index];
		inbound_sa = ipsec_sad_add((sad_entry *)&test_case->inbound_sa_template, &(*databases)->inbound_sad);
		if(inbound_sa == NULL)
		{
			return 1;
		}
		ipsec_sad_reset_replay(inbound_sa);

		if(test_case->family == IPSEC_AF_INET6)
		{
			inbound_spd = ipsec_spd_add_ipv6(test_case->inbound_spd_template.src_ipv6, test_case->inbound_spd_template.src_netaddr_ipv6,
								   test_case->inbound_spd_template.dest_ipv6, test_case->inbound_spd_template.dest_netaddr_ipv6,
								   test_case->inbound_spd_template.protocol, test_case->inbound_spd_template.src_port,
								   test_case->inbound_spd_template.dest_port, test_case->inbound_spd_template.policy,
								   &(*databases)->inbound_spd);
		}
		else
		{
			inbound_spd = ipsec_spd_add(test_case->inbound_spd_template.src, test_case->inbound_spd_template.src_netaddr,
							  test_case->inbound_spd_template.dest, test_case->inbound_spd_template.dest_netaddr,
							  test_case->inbound_spd_template.protocol, test_case->inbound_spd_template.src_port,
							  test_case->inbound_spd_template.dest_port, test_case->inbound_spd_template.policy,
							  &(*databases)->inbound_spd);
		}

		if(inbound_spd == NULL)
		{
			return 1;
		}

		ipsec_spd_add_sa(inbound_spd, inbound_sa);
	}

	return 0;
}

static int packet_dump_verify(const char *path)
{
	packet_dump_case cases[4];
	size_t case_count;
	FILE *stream;
	packet_dump_pcap_header pcap_header;
	size_t index;
	spd_entry inbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	spd_entry outbound_spd_data[IPSEC_MAX_SPD_ENTRIES];
	sad_entry inbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	sad_entry outbound_sad_data[IPSEC_MAX_SAD_ENTRIES];
	db_set_netif *databases;

	packet_dump_prepare_cases(cases, &case_count);
	stream = fopen(path, "rb");
	if(stream == NULL)
	{
		fprintf(stderr, "failed to open input file: %s\n", path);
		return 1;
	}

	if(fread(&pcap_header, sizeof(pcap_header), 1, stream) != 1)
	{
		fprintf(stderr, "failed to read PCAP header\n");
		fclose(stream);
		return 1;
	}

	if((pcap_header.magic != PACKET_DUMP_PCAP_MAGIC) || (pcap_header.network != PACKET_DUMP_PCAP_LINKTYPE_RAW))
	{
		fprintf(stderr, "unsupported PCAP file\n");
		fclose(stream);
		return 1;
	}

	if(packet_dump_prepare_verify_db(cases, case_count, inbound_spd_data, outbound_spd_data, inbound_sad_data, outbound_sad_data, &databases) != 0)
	{
		fprintf(stderr, "failed to prepare verification databases\n");
		fclose(stream);
		return 1;
	}

	for(index = 0; index < case_count; index++)
	{
		packet_dump_pcap_record_header record_header;
		unsigned char packet_buffer[PACKET_DUMP_MAX_PACKET_SIZE];
		int payload_offset;
		int payload_len;
		int status;
		packet_dump_case *test_case;

		if(fread(&record_header, sizeof(record_header), 1, stream) != 1)
		{
			fprintf(stderr, "missing packet record %lu\n", (unsigned long)(index + 1));
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		if(record_header.incl_len > sizeof(packet_buffer))
		{
			fprintf(stderr, "packet too large in capture\n");
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		if(fread(packet_buffer, (size_t)record_header.incl_len, 1, stream) != 1)
		{
			fprintf(stderr, "failed to read packet payload\n");
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		test_case = &cases[index];
		payload_offset = 0;
		payload_len = 0;
		status = ipsec_input(packet_buffer, (int)record_header.incl_len, &payload_offset, &payload_len, databases);
		if(status != IPSEC_STATUS_SUCCESS)
		{
			fprintf(stderr, "verification failed for %s: %d\n", test_case->name, status);
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		if((payload_len != test_case->original_len) || (memcmp(packet_buffer + payload_offset, test_case->original, (size_t)test_case->original_len) != 0))
		{
			fprintf(stderr, "roundtrip mismatch for %s\n", test_case->name);
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		printf("verified %s\n", test_case->name);
	}

	if(fgetc(stream) != EOF)
	{
		fprintf(stderr, "capture contains more packets than expected\n");
		ipsec_spd_release_dbs(databases);
		fclose(stream);
		return 1;
	}

	ipsec_spd_release_dbs(databases);
	fclose(stream);
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode;
	const char *path;

	if(argc != 3)
	{
		fprintf(stderr, "usage: %s <generate|verify|roundtrip> <dump.pcap>\n", argv[0]);
		return 1;
	}

	mode = argv[1];
	path = argv[2];

	if(strcmp(mode, "generate") == 0)
	{
		return packet_dump_generate(path);
	}

	if(strcmp(mode, "verify") == 0)
	{
		return packet_dump_verify(path);
	}

	if(strcmp(mode, "roundtrip") == 0)
	{
		if(packet_dump_generate(path) != 0)
		{
			return 1;
		}
		return packet_dump_verify(path);
	}

	fprintf(stderr, "unknown mode: %s\n", mode);
	return 1;
}