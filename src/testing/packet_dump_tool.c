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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipsec/ah.h"
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
#define PACKET_DUMP_CASE_COUNT           (10)

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
	const char *label;
	__u8 family;
	__u8 protocol;
	__u8 mode;
	__u8 enc_alg;
	__u8 auth_alg;
	__u32 spi;
	__u16 src_port;
	__u16 dst_port;
	__u32 inner_src_ipv4;
	__u32 inner_dst_ipv4;
	__u32 outer_src_ipv4;
	__u32 outer_dst_ipv4;
	__u8 inner_src_ipv6[16];
	__u8 inner_dst_ipv6[16];
	__u8 outer_src_ipv6[16];
	__u8 outer_dst_ipv6[16];
	int original_len;
	unsigned char original[IPSEC_MTU];
	spd_entry outbound_spd;
	spd_entry inbound_spd_template;
	sad_entry outbound_sa;
	sad_entry inbound_sa_template;
} packet_dump_case;

static const __u8 packet_dump_mask_full[16] =
{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const __u8 packet_dump_aes_key[16] =
{
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const __u8 packet_dump_3des_key[24] =
{
	0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
	0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
	0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67
};

static const __u8 packet_dump_auth_key[20] =
{
	0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
	0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
	0x89, 0xab, 0xcd, 0xef
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

static const char *packet_dump_family_name(__u8 family)
{
	return family == IPSEC_AF_INET6 ? "IPv6" : "IPv4";
}

static const char *packet_dump_protocol_name(__u8 protocol)
{
	return protocol == IPSEC_PROTO_AH ? "AH" : "ESP";
}

static const char *packet_dump_mode_name(__u8 mode)
{
	return mode == IPSEC_TUNNEL ? "tunnel" : "transport";
}

static const char *packet_dump_enc_name(__u8 enc_alg)
{
	switch(enc_alg)
	{
		case IPSEC_AES_CBC:
			return "AES-CBC";
		case IPSEC_3DES:
			return "3DES-CBC";
		default:
			return "none";
	}
}

static const char *packet_dump_auth_name(__u8 auth_alg)
{
	switch(auth_alg)
	{
		case IPSEC_HMAC_MD5:
			return "HMAC-MD5-96";
		case IPSEC_HMAC_SHA1:
			return "HMAC-SHA1-96";
		default:
			return "none";
	}
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

static void packet_dump_fill_sa_keys(sad_entry *sa, __u8 enc_alg, __u8 auth_alg)
{
	if(enc_alg == IPSEC_AES_CBC)
	{
		memcpy(sa->enckey, packet_dump_aes_key, sizeof(packet_dump_aes_key));
	}
	else if(enc_alg == IPSEC_3DES)
	{
		memcpy(sa->enckey, packet_dump_3des_key, sizeof(packet_dump_3des_key));
	}

	if(auth_alg != 0)
	{
		memcpy(sa->authkey, packet_dump_auth_key, sizeof(packet_dump_auth_key));
	}
}

static sad_entry packet_dump_make_ipv4_sa(__u32 spi, __u8 protocol, __u8 mode, __u8 enc_alg, __u8 auth_alg, __u32 dest)
{
	sad_entry sa;

	memset(&sa, 0, sizeof(sa));
	sa.dest = dest;
	sa.dest_netaddr = ipsec_inet_addr("255.255.255.255");
	sa.spi = ipsec_htonl(spi);
	sa.protocol = protocol;
	sa.mode = mode;
	sa.replay_win = IPSEC_SEQ_MAX_WINDOW;
	sa.path_mtu = 1450;
	sa.enc_alg = enc_alg;
	sa.auth_alg = auth_alg;
	sa.use_flag = IPSEC_USED;
	packet_dump_fill_sa_keys(&sa, enc_alg, auth_alg);
	return sa;
}

static sad_entry packet_dump_make_ipv6_sa(__u32 spi, __u8 protocol, __u8 mode, __u8 enc_alg, __u8 auth_alg, const __u8 *dest)
{
	sad_entry sa;

	memset(&sa, 0, sizeof(sa));
	sa.spi = ipsec_htonl(spi);
	sa.protocol = protocol;
	sa.mode = mode;
	sa.replay_win = IPSEC_SEQ_MAX_WINDOW;
	sa.path_mtu = 1450;
	sa.enc_alg = enc_alg;
	sa.auth_alg = auth_alg;
	sa.use_flag = IPSEC_USED;
	ipsec_sad_set_ipv6(&sa, dest, packet_dump_mask_full);
	packet_dump_fill_sa_keys(&sa, enc_alg, auth_alg);
	return sa;
}

static void packet_dump_configure_spd_ipv4(spd_entry *spd, __u32 src, __u32 dst, __u16 src_port, __u16 dst_port)
{
	memset(spd, 0, sizeof(*spd));
	spd->src = src;
	spd->src_netaddr = ipsec_inet_addr("255.255.255.255");
	spd->dest = dst;
	spd->dest_netaddr = ipsec_inet_addr("255.255.255.255");
	spd->protocol = IPSEC_PROTO_TCP;
	spd->src_port = ipsec_htons(src_port);
	spd->dest_port = ipsec_htons(dst_port);
	spd->policy = POLICY_APPLY;
	spd->use_flag = IPSEC_USED;
}

static void packet_dump_configure_spd_ipv6(spd_entry *spd, const __u8 *src, const __u8 *dst, __u16 src_port, __u16 dst_port)
{
	memset(spd, 0, sizeof(*spd));
	ipsec_spd_set_ipv6(spd, src, packet_dump_mask_full, dst, packet_dump_mask_full);
	spd->protocol = IPSEC_PROTO_TCP;
	spd->src_port = ipsec_htons(src_port);
	spd->dest_port = ipsec_htons(dst_port);
	spd->policy = POLICY_APPLY;
	spd->use_flag = IPSEC_USED;
}

static void packet_dump_set_case_ipv4(packet_dump_case *test_case, const char *name, __u8 protocol, __u8 mode,
					      __u8 enc_alg, __u8 auth_alg, __u32 spi,
					      __u16 src_port, __u16 dst_port,
					      __u32 inner_src, __u32 inner_dst,
					      __u32 outer_src, __u32 outer_dst)
{
	memset(test_case, 0, sizeof(*test_case));
	test_case->name = name;
	test_case->family = IPSEC_AF_INET;
	test_case->protocol = protocol;
	test_case->mode = mode;
	test_case->enc_alg = enc_alg;
	test_case->auth_alg = auth_alg;
	test_case->spi = spi;
	test_case->src_port = src_port;
	test_case->dst_port = dst_port;
	test_case->inner_src_ipv4 = inner_src;
	test_case->inner_dst_ipv4 = inner_dst;
	test_case->outer_src_ipv4 = outer_src;
	test_case->outer_dst_ipv4 = outer_dst;
	packet_dump_init_ipv4_tcp_packet(test_case->original, inner_src, inner_dst, src_port, dst_port);
	test_case->original_len = IPSEC_IPV4_HDR_SIZE + (int)sizeof(ipsec_tcp_header);
	test_case->outbound_sa = packet_dump_make_ipv4_sa(spi, protocol, mode, enc_alg, auth_alg, outer_dst);
	test_case->inbound_sa_template = packet_dump_make_ipv4_sa(spi, protocol, mode, enc_alg, auth_alg, outer_dst);
	packet_dump_configure_spd_ipv4(&test_case->outbound_spd, inner_src, inner_dst, src_port, dst_port);
	packet_dump_configure_spd_ipv4(&test_case->inbound_spd_template, inner_src, inner_dst, src_port, dst_port);
	ipsec_spd_add_sa(&test_case->outbound_spd, &test_case->outbound_sa);
	ipsec_sad_reset_replay(&test_case->outbound_sa);
	ipsec_sad_reset_replay(&test_case->inbound_sa_template);
	test_case->inbound_sa_template.sequence_number = 0;
}

static void packet_dump_set_case_ipv6(packet_dump_case *test_case, const char *name, __u8 protocol, __u8 mode,
					      __u8 enc_alg, __u8 auth_alg, __u32 spi,
					      __u16 src_port, __u16 dst_port,
					      const __u8 *inner_src, const __u8 *inner_dst,
					      const __u8 *outer_src, const __u8 *outer_dst)
{
	memset(test_case, 0, sizeof(*test_case));
	test_case->name = name;
	test_case->family = IPSEC_AF_INET6;
	test_case->protocol = protocol;
	test_case->mode = mode;
	test_case->enc_alg = enc_alg;
	test_case->auth_alg = auth_alg;
	test_case->spi = spi;
	test_case->src_port = src_port;
	test_case->dst_port = dst_port;
	memcpy(test_case->inner_src_ipv6, inner_src, 16);
	memcpy(test_case->inner_dst_ipv6, inner_dst, 16);
	memcpy(test_case->outer_src_ipv6, outer_src, 16);
	memcpy(test_case->outer_dst_ipv6, outer_dst, 16);
	packet_dump_init_ipv6_tcp_packet(test_case->original, inner_src, inner_dst, src_port, dst_port);
	test_case->original_len = IPSEC_IPV6_HDR_SIZE + (int)sizeof(ipsec_tcp_header);
	test_case->outbound_sa = packet_dump_make_ipv6_sa(spi, protocol, mode, enc_alg, auth_alg, outer_dst);
	test_case->inbound_sa_template = packet_dump_make_ipv6_sa(spi, protocol, mode, enc_alg, auth_alg, outer_dst);
	packet_dump_configure_spd_ipv6(&test_case->outbound_spd, inner_src, inner_dst, src_port, dst_port);
	packet_dump_configure_spd_ipv6(&test_case->inbound_spd_template, inner_src, inner_dst, src_port, dst_port);
	ipsec_spd_add_sa(&test_case->outbound_spd, &test_case->outbound_sa);
	ipsec_sad_reset_replay(&test_case->outbound_sa);
	ipsec_sad_reset_replay(&test_case->inbound_sa_template);
	test_case->inbound_sa_template.sequence_number = 0;
}

static void packet_dump_prepare_label(packet_dump_case *test_case, char *buffer, size_t buffer_size)
{
	_snprintf(buffer, buffer_size,
		"%s | proto=%s | mode=%s | enc=%s | auth=%s",
		test_case->name,
		packet_dump_protocol_name(test_case->protocol),
		packet_dump_mode_name(test_case->mode),
		packet_dump_enc_name(test_case->enc_alg),
		packet_dump_auth_name(test_case->auth_alg));
	buffer[buffer_size - 1] = '\0';
	test_case->label = buffer;
}

static void packet_dump_prepare_cases(packet_dump_case *cases, size_t *case_count)
{
	static char labels[PACKET_DUMP_CASE_COUNT][160];
	size_t index;

	*case_count = PACKET_DUMP_CASE_COUNT;

	packet_dump_set_case_ipv4(&cases[0], "ipv4-ah-transport-md5", IPSEC_PROTO_AH, IPSEC_TRANSPORT,
		0, IPSEC_HMAC_MD5, 0x6101, 1101, 2101,
		ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("192.168.1.20"),
		ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("192.168.1.20"));

	packet_dump_set_case_ipv4(&cases[1], "ipv4-ah-tunnel-sha1", IPSEC_PROTO_AH, IPSEC_TUNNEL,
		0, IPSEC_HMAC_SHA1, 0x6102, 1102, 2102,
		ipsec_inet_addr("10.0.0.10"), ipsec_inet_addr("10.0.0.20"),
		ipsec_inet_addr("192.168.10.1"), ipsec_inet_addr("192.168.20.1"));

	packet_dump_set_case_ipv6(&cases[2], "ipv6-ah-transport-sha1", IPSEC_PROTO_AH, IPSEC_TRANSPORT,
		0, IPSEC_HMAC_SHA1, 0x6103, 1103, 2103,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst);

	packet_dump_set_case_ipv6(&cases[3], "ipv6-ah-tunnel-md5", IPSEC_PROTO_AH, IPSEC_TUNNEL,
		0, IPSEC_HMAC_MD5, 0x6104, 1104, 2104,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst,
		packet_dump_ipv6_tunnel_src, packet_dump_ipv6_tunnel_dst);

	packet_dump_set_case_ipv4(&cases[4], "ipv4-esp-transport-aes", IPSEC_PROTO_ESP, IPSEC_TRANSPORT,
		IPSEC_AES_CBC, 0, 0x6201, 1201, 2201,
		ipsec_inet_addr("192.168.2.10"), ipsec_inet_addr("192.168.2.20"),
		ipsec_inet_addr("192.168.2.10"), ipsec_inet_addr("192.168.2.20"));

	packet_dump_set_case_ipv4(&cases[5], "ipv4-esp-transport-aes-sha1", IPSEC_PROTO_ESP, IPSEC_TRANSPORT,
		IPSEC_AES_CBC, IPSEC_HMAC_SHA1, 0x6202, 1202, 2202,
		ipsec_inet_addr("192.168.3.10"), ipsec_inet_addr("192.168.3.20"),
		ipsec_inet_addr("192.168.3.10"), ipsec_inet_addr("192.168.3.20"));

	packet_dump_set_case_ipv4(&cases[6], "ipv4-esp-tunnel-3des", IPSEC_PROTO_ESP, IPSEC_TUNNEL,
		IPSEC_3DES, 0, 0x6203, 1203, 2203,
		ipsec_inet_addr("10.1.0.10"), ipsec_inet_addr("10.1.0.20"),
		ipsec_inet_addr("192.168.30.1"), ipsec_inet_addr("192.168.40.1"));

	packet_dump_set_case_ipv6(&cases[7], "ipv6-esp-transport-aes-sha1", IPSEC_PROTO_ESP, IPSEC_TRANSPORT,
		IPSEC_AES_CBC, IPSEC_HMAC_SHA1, 0x6204, 1204, 2204,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst);

	packet_dump_set_case_ipv6(&cases[8], "ipv6-esp-tunnel-3des", IPSEC_PROTO_ESP, IPSEC_TUNNEL,
		IPSEC_3DES, 0, 0x6205, 1205, 2205,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst,
		packet_dump_ipv6_tunnel_src, packet_dump_ipv6_tunnel_dst);

	packet_dump_set_case_ipv6(&cases[9], "ipv6-esp-tunnel-aes-sha1", IPSEC_PROTO_ESP, IPSEC_TUNNEL,
		IPSEC_AES_CBC, IPSEC_HMAC_SHA1, 0x6206, 1206, 2206,
		packet_dump_ipv6_transport_src, packet_dump_ipv6_transport_dst,
		packet_dump_ipv6_tunnel_src, packet_dump_ipv6_tunnel_dst);

	for(index = 0; index < PACKET_DUMP_CASE_COUNT; index++)
	{
		packet_dump_prepare_label(&cases[index], labels[index], sizeof(labels[index]));
	}
}

static char *packet_dump_label_path(const char *pcap_path)
{
	size_t len;
	char *path;

	len = strlen(pcap_path) + strlen(".labels.txt") + 1;
	path = (char *)malloc(len);
	if(path == NULL)
	{
		return NULL;
	}

	_snprintf(path, len, "%s.labels.txt", pcap_path);
	path[len - 1] = '\0';
	return path;
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

static int packet_dump_write_labels(const char *pcap_path, packet_dump_case *cases, const int *packet_lengths, size_t case_count)
{
	FILE *stream;
	char *label_path;
	size_t index;

	label_path = packet_dump_label_path(pcap_path);
	if(label_path == NULL)
	{
		fprintf(stderr, "failed to build label path\n");
		return 1;
	}

	stream = fopen(label_path, "wb");
	if(stream == NULL)
	{
		fprintf(stderr, "failed to open label file: %s\n", label_path);
		free(label_path);
		return 1;
	}

	for(index = 0; index < case_count; index++)
	{
		fprintf(stream,
			"frame=%lu bytes=%d family=%s label=%s\n",
			(unsigned long)(index + 1),
			packet_lengths[index],
			packet_dump_family_name(cases[index].family),
			cases[index].label);
	}

	fclose(stream);
	printf("wrote labels %s\n", label_path);
	free(label_path);
	return 0;
}

static int packet_dump_generate(const char *path)
{
	packet_dump_case cases[PACKET_DUMP_CASE_COUNT];
	size_t case_count;
	FILE *stream;
	size_t index;
	int packet_lengths[PACKET_DUMP_CASE_COUNT];

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

		packet_lengths[index] = payload_len;
		printf("wrote %s (%d bytes)\n", test_case->label, payload_len);
	}

	fclose(stream);
	return packet_dump_write_labels(path, cases, packet_lengths, case_count);
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
	packet_dump_case cases[PACKET_DUMP_CASE_COUNT];
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
			fprintf(stderr, "verification failed for %s: %d\n", test_case->label, status);
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		if((payload_len != test_case->original_len) || (memcmp(packet_buffer + payload_offset, test_case->original, (size_t)test_case->original_len) != 0))
		{
			fprintf(stderr, "roundtrip mismatch for %s\n", test_case->label);
			ipsec_spd_release_dbs(databases);
			fclose(stream);
			return 1;
		}

		printf("verified %s\n", test_case->label);
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