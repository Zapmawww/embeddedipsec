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

/** @file ah.c
 *  @brief RFC2402 - IP Authentication Header (AH)
 *
 *  @author  Christian Scheurer <http://www.christianscheurer.ch>
 *
 *  <B>OUTLINE:</B>
 * The AH functions are used to authenticate IPsec traffic.
 *
 *  <B>IMPLEMENTATION:</B>
 * All functions work in-place (i.g. manipulate directly the original
 * packet without copying any data). For the encapsulation routine,
 * the caller must ensure that space for the new IP and AH header are
 * available in front of the packet:
 *
 *  <pre>
 *                                  | pointer to packet header
 *     ____________________________\/_____________________________
 *    |          �       �         �                              |
 *    | Ethernet � newIP � AH, ICV �   original (inner) packet    |
 *    |__________�_______�_________�______________________________|
 *    �                            �
 *    �<-- room for new headers -->�
 *  </pre>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#include <string.h>

#include "ipsec/ipsec.h"
#include "ipsec/util.h"
#include "ipsec/debug.h"

#include "ipsec/sa.h"
#include "ipsec/md5.h"
#include "ipsec/sha1.h"

#include "ipsec/ah.h"



__u32 ipsec_ah_bitmap 	= 0;        		/**< save session state to detect replays - must be 32 bits. 
											 *   Note: must be initialized with zero (0x00000000) when
											 *         a new SA is established! */
__u32 ipsec_ah_lastSeq 	= 0;         		/**< save session state to detect replays
											 *   Note: must be initialized with zero (0x00000000) when
											 *         a new SA is established! */

static void ipsec_ah_save_mutable_fields(const void *packet, __u8 *tos, __u16 *offset, __u8 *hop_limit)
{
	if(ipsec_packet_family(packet) == IPSEC_AF_INET6)
	{
		*tos = 0;
		*offset = 0;
		*hop_limit = ((const ipsec_ipv6_header *)packet)->hop_limit;
		return;
	}

	*tos = ((const ipsec_ip_header *)packet)->tos;
	*offset = ((const ipsec_ip_header *)packet)->offset;
	*hop_limit = ((const ipsec_ip_header *)packet)->ttl;
}

static void ipsec_ah_finalize_packet(void *packet, int total_len, __u8 protocol, __u8 tos, __u16 offset, __u8 hop_limit)
{
	ipsec_packet_set_total_len(packet, total_len);
	ipsec_packet_set_protocol(packet, protocol);

	if(ipsec_packet_family(packet) == IPSEC_AF_INET6)
	{
		((ipsec_ipv6_header *)packet)->hop_limit = hop_limit;
		return;
	}

	((ipsec_ip_header *)packet)->tos = tos;
	((ipsec_ip_header *)packet)->offset = offset;
	((ipsec_ip_header *)packet)->ttl = hop_limit;
	((ipsec_ip_header *)packet)->chksum = 0;
	((ipsec_ip_header *)packet)->chksum = ipsec_ip_chksum(packet, sizeof(ipsec_ip_header));
}

static void ipsec_ah_init_outer_ipv4(ipsec_ip_header *header, int total_len, __u32 src, __u32 dst)
{
	header->v_hl = 0x45;
	header->tos = 0;
	header->len = ipsec_htons((__u16)total_len);
	header->id = 1000;
	header->offset = 0;
	header->ttl = 0;
	header->protocol = IPSEC_PROTO_AH;
	header->chksum = 0;
	header->src = src;
	header->dest = dst;
}

static void ipsec_ah_init_outer_ipv6(ipsec_ipv6_header *header, int total_len, const __u8 *src, const __u8 *dst)
{
	header->v_tc_fl = ipsec_htonl(6UL << 28);
	header->payload_len = ipsec_htons((__u16)(total_len - IPSEC_IPV6_HDR_SIZE));
	header->nexthdr = IPSEC_PROTO_AH;
	header->hop_limit = 0;
	memcpy(header->src, src, 16);
	memcpy(header->dest, dst, 16);
}

static int ipsec_ah_encapsulate_common(void *inner_packet, int *payload_offset, int *payload_size,
								 sad_entry *sa, __u8 outer_family, const void *src, const void *dst)
{
	#if !IPSEC_ENABLE_AH
	(void)inner_packet;
	(void)payload_offset;
	(void)payload_size;
	(void)sa;
	(void)outer_family;
	(void)src;
	(void)dst;
	return IPSEC_STATUS_NOT_IMPLEMENTED;
	#else
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;
	int outer_header_len;
	int inner_len;
	int ip_header_len;
	int transport_len;
	__u8 inner_family;
	__u8 original_protocol;
	__u8 saved_tos;
	__u16 saved_offset;
	__u8 saved_hop_limit;
	ipsec_ah_header *new_ah_header;
	unsigned char digest[IPSEC_MAX_AUTHKEY_LEN];

	outer_header_len = outer_family == IPSEC_AF_INET6 ? IPSEC_IPV6_HDR_SIZE : IPSEC_IPV4_HDR_SIZE;
	inner_family = ipsec_packet_family(inner_packet);
	inner_len = ipsec_packet_total_len(inner_packet);
	ip_header_len = ipsec_packet_header_len(inner_packet);
	original_protocol = ipsec_packet_protocol(inner_packet);

	if(ipsec_packet_hop_limit(inner_packet) == 0)
	{
		return IPSEC_STATUS_TTL_EXPIRED;
	}

	if(IPSEC_AUTH_ICV != 12)
	{
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	sa->sequence_number++;
	ipsec_ah_save_mutable_fields(inner_packet, &saved_tos, &saved_offset, &saved_hop_limit);

	if(sa->mode == IPSEC_TRANSPORT)
	{
		#if !IPSEC_ENABLE_TRANSPORT_MODE
		return IPSEC_STATUS_NOT_IMPLEMENTED;
		#else
		transport_len = inner_len - ip_header_len;
		memmove(((unsigned char *)inner_packet) + ip_header_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV,
				((unsigned char *)inner_packet) + ip_header_len,
				transport_len);
		new_ah_header = (ipsec_ah_header *)(((unsigned char *)inner_packet) + ip_header_len);
		new_ah_header->nexthdr = original_protocol;
		new_ah_header->len = 0x04;
		new_ah_header->reserved = 0x0000;
		new_ah_header->spi = sa->spi;
		new_ah_header->sequence = ipsec_htonl(sa->sequence_number);
		memset(new_ah_header->ah_data, '\0', IPSEC_AUTH_ICV);

		ipsec_ah_finalize_packet(inner_packet,
						 inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV,
						 IPSEC_PROTO_AH,
						 0,
						 0,
						 0);
		ipsec_packet_zero_mutable_fields(inner_packet);
		#endif
	}
	else if(sa->mode == IPSEC_TUNNEL)
	{
		#if !IPSEC_ENABLE_TUNNEL_MODE
		return IPSEC_STATUS_NOT_IMPLEMENTED;
		#else
		new_ah_header = (ipsec_ah_header *)(((char *)inner_packet) - IPSEC_AUTH_ICV - IPSEC_AH_HDR_SIZE);
		new_ah_header->nexthdr = inner_family == IPSEC_AF_INET6 ? IPSEC_PROTO_IPV6 : IPSEC_PROTO_IPIP;
		new_ah_header->len = 0x04;
		new_ah_header->reserved = 0x0000;
		new_ah_header->spi = sa->spi;
		new_ah_header->sequence = ipsec_htonl(sa->sequence_number);
		memset(new_ah_header->ah_data, '\0', IPSEC_AUTH_ICV);

		if(outer_family == IPSEC_AF_INET6)
		{
			ipsec_ah_init_outer_ipv6((ipsec_ipv6_header *)(((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len),
							   inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len,
							   (const __u8 *)src, (const __u8 *)dst);
		}
		else
		{
			ipsec_ip_header *new_ip_header;
			new_ip_header = (ipsec_ip_header *)(((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len);
			ipsec_ah_init_outer_ipv4(new_ip_header, inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len,
							 *((const __u32 *)src), *((const __u32 *)dst));
		}
		#endif
	}
	else
	{
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	switch(sa->auth_alg) {
		case IPSEC_HMAC_MD5:
			hmac_md5((unsigned char *)(sa->mode == IPSEC_TRANSPORT ? inner_packet : (((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len)),
				 (sa->mode == IPSEC_TRANSPORT ? inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV : inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len),
				 (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
			break;
		case IPSEC_HMAC_SHA1:
			hmac_sha1((unsigned char *)(sa->mode == IPSEC_TRANSPORT ? inner_packet : (((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len)),
				  (sa->mode == IPSEC_TRANSPORT ? inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV : inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len),
				  (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
			break;
		default:
			return IPSEC_STATUS_FAILURE;
	}

	memcpy(new_ah_header->ah_data, digest, IPSEC_AUTH_ICV);

	if(sa->mode == IPSEC_TRANSPORT)
	{
		ipsec_ah_finalize_packet(inner_packet,
						 inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV,
						 IPSEC_PROTO_AH,
						 saved_tos,
						 saved_offset,
						 saved_hop_limit);
		*payload_size = inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV;
		*payload_offset = 0;
		return IPSEC_STATUS_SUCCESS;
	}

	if(outer_family == IPSEC_AF_INET6)
	{
		ipsec_ipv6_header *new_ip6_header;
		new_ip6_header = (ipsec_ipv6_header *)(((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len);
		new_ip6_header->hop_limit = 64;
	}
	else
	{
		ipsec_ip_header *new_ip_header;
		new_ip_header = (ipsec_ip_header *)(((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len);
		new_ip_header->ttl = 64;
		new_ip_header->chksum = ipsec_ip_chksum(new_ip_header, sizeof(ipsec_ip_header));
	}

	*payload_size = inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len;
	*payload_offset = (((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len) - ((char *)inner_packet);

	ret_val = IPSEC_STATUS_SUCCESS;
	return ret_val;
	#endif
}



/**
 * Checks AH header and ICV (RFC 2402).
 * Mutable fields of the outer IP header are set to zero prior to the ICV calculation.
 *
 * @todo Extend function to support transport mode
 *
 * @param	outer_packet   pointer used to access the (outer) IP packet which hast to be checked
 * @param   payload_offset  pointer used to return offset of inner (original) IP packet relative to the start of the outer header
 * @param   payload_size    pointer used to return total size of the inner (original) IP packet
 * @param 	sa              pointer to security association holding the secret authentication key
 *
 * @return IPSEC_STATUS_SUCCESS	        packet could be authenticated
 * @return IPSEC_STATUS_FAILURE         packet is corrupted or ICV does not match
 * @return IPSEC_STATUS_NOT_IMPLEMENTED invalid mode (only IPSEC_TUNNEL mode is implemented)
 */
int ipsec_ah_check(void *outer_packet, int *payload_offset, int *payload_size,
 				    sad_entry *sa)
{
	#if !IPSEC_ENABLE_AH
	(void)outer_packet;
	(void)payload_offset;
	(void)payload_size;
	(void)sa;
	return IPSEC_STATUS_NOT_IMPLEMENTED;
	#else
	int ret_val 	= IPSEC_STATUS_NOT_INITIALIZED;	/* by default, the return value is undefined */
	ipsec_ah_header *ah_header;
	int ah_len;
	int ah_offs;
	int packet_len;
	int new_len;
	__u8 saved_tos;
	__u16 saved_offset;
	__u8 saved_hop_limit;
	__u8 original_protocol;
	unsigned char orig_digest[IPSEC_MAX_AUTHKEY_LEN];
	unsigned char digest[IPSEC_MAX_AUTHKEY_LEN];

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
	              "ipsec_ah_check",
				  ("outer_packet=%p, *payload_offset=%d, *payload_size=%d sa=%p",
			      (void *)outer_packet, *payload_offset, *payload_size, (void *)sa)
				 );

	/* The AH header is expected to be 24 bytes since we support only 96 bit authentication values */
	ah_offs = ipsec_packet_header_len(outer_packet);
	ah_len = (IPSEC_AH_HDR_SIZE - 4) + ( ((ipsec_ah_header *)((unsigned char *)outer_packet + ah_offs))->len << 2 );
	packet_len = ipsec_packet_total_len(outer_packet);

	/* minimal AH header + ICV */
	if(ah_len != IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV)
	{
		IPSEC_LOG_DBG("ipsec_ah_check", IPSEC_STATUS_FAILURE, ("wrong AH header size: ah_len=%d (must be 24 bytes, only 96bit authentication values allowed)", ah_len) );
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_FAILURE) );
		return IPSEC_STATUS_FAILURE;
	}
	
	ah_header = ((ipsec_ah_header *)((unsigned char *)outer_packet + ah_offs));

	/* preliminary anti-replay check (without updating the global sequence number window)     */
	/* This check prevents useless ICV calculation if the Sequence Number is obviously wrong  */
	ret_val = ipsec_check_replay_window(ipsec_ntohl(ah_header->sequence), ipsec_ah_lastSeq, ipsec_ah_bitmap);
	if(ret_val != IPSEC_AUDIT_SUCCESS)
	{
		IPSEC_LOG_AUD("ipsec_ah_check", IPSEC_AUDIT_SEQ_MISMATCH, ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", ipsec_ah_lastSeq, ipsec_ntohl(ah_header->sequence), IPSEC_SEQ_MAX_WINDOW) );
		return ret_val;
	}
	
	ipsec_ah_save_mutable_fields(outer_packet, &saved_tos, &saved_offset, &saved_hop_limit);

	/* zero all mutable fields prior to ICV calculation */
	/* mutuable fields according to RFC2402, 3.3.3.1.1.1. */
	ipsec_packet_zero_mutable_fields(outer_packet);

	/* backup 96bit HMAC before setting it to 0 */
	memcpy(orig_digest, ah_header->ah_data, IPSEC_AUTH_ICV);
	memset(((ipsec_ah_header *)((unsigned char *)outer_packet + ah_offs))->ah_data, '\0', IPSEC_AUTH_ICV);

	if((sa->mode != IPSEC_TUNNEL) && (sa->mode != IPSEC_TRANSPORT))
	{
		IPSEC_LOG_ERR("ipsec_ah_check", IPSEC_STATUS_NOT_IMPLEMENTED, ("Can't handle mode %d.", sa->mode) );
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	switch(sa->auth_alg) {

		case IPSEC_HMAC_MD5:
			hmac_md5((unsigned char *)outer_packet, packet_len,
			         (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
			break;
		case IPSEC_HMAC_SHA1:
			hmac_sha1((unsigned char *)outer_packet, packet_len,
			          (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
			break;
		default:
			IPSEC_LOG_ERR("ipsec_ah_check", IPSEC_STATUS_FAILURE, ("unknown HASH algorithm for this AH")) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
	}

	if(memcmp(orig_digest, digest, IPSEC_AUTH_ICV) != 0) {
		IPSEC_LOG_ERR("ipsec_ah_check", IPSEC_STATUS_FAILURE, ("AH ICV does not match")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_FAILURE) );
		return IPSEC_STATUS_FAILURE;
	}
	
	/* post-ICV calculationn anti-replay check (this call will update the global sequence number window) */
	ret_val = ipsec_update_replay_window(ipsec_ntohl(ah_header->sequence), (__u32 *)&ipsec_ah_lastSeq, (__u32 *)&ipsec_ah_bitmap);
	if(ret_val != IPSEC_AUDIT_SUCCESS)
	{
		IPSEC_LOG_AUD("ipsec_ah_check", IPSEC_AUDIT_SEQ_MISMATCH, ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", ipsec_ah_lastSeq, ipsec_ntohl(ah_header->sequence), IPSEC_SEQ_MAX_WINDOW) );
		return ret_val;
	}

	if(sa->mode == IPSEC_TRANSPORT)
	{
		#if !IPSEC_ENABLE_TRANSPORT_MODE
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
		#else
		original_protocol = ah_header->nexthdr;
		new_len = packet_len - ah_len;
		memmove(((unsigned char *)outer_packet) + ah_offs,
				((unsigned char *)outer_packet) + ah_offs + ah_len,
				packet_len - ah_offs - ah_len);
		ipsec_ah_finalize_packet(outer_packet, new_len, original_protocol, saved_tos, saved_offset, saved_hop_limit);
		*payload_offset = 0;
		*payload_size = new_len;
		#endif
	}
	else if(sa->mode == IPSEC_TUNNEL)
	{
		#if !IPSEC_ENABLE_TUNNEL_MODE
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
		#else
		*payload_offset = ah_offs + ah_len;
		*payload_size   = ipsec_packet_total_len((unsigned char *)outer_packet + ah_offs + ah_len);
		#endif
	}
	else
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS;
	#endif
}


/**
 * Adds AH and outer IP header, calculates ICV (RFC 2402).
 *
 * @warning Attention: this function requires room (IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + IPSEC_MIN_IPHDR_SIZE)
 *          in front of the inner_packet pointer to add outer IP header and AH header. Depending on the
 *          TCP/IP stack implementation, additional space for the Link layer (Ethernet header) should be added).
 *
 * @todo Extend function to support transport mode
 *
 * @param	inner_packet   pointer used to access the (outer) IP packet which hast to be checked
 * @param   payload_offset  pointer used to return offset of inner (original) IP packet relative to the start of the outer header
 * @param   payload_size    pointer used to return total size of the inner (original) IP packet
 * @param   src             IP address of the local tunnel start point (external IP address)
 * @param   dst             IP address of the remote tunnel end point (external IP address)
 * @param 	sa              pointer to security association holding the secret authentication key
 * @return IPSEC_STATUS_SUCCESS	        packet could be authenticated
 * @return IPSEC_STATUS_FAILURE         packet is corrupted or ICV does not match
 * @return IPSEC_STATUS_NOT_IMPLEMENTED invalid mode (only IPSEC_TUNNEL mode is implemented)
 */
int ipsec_ah_encapsulate(ipsec_ip_header *inner_packet, int *payload_offset, int *payload_size,
						 sad_entry *sa, __u32 src, __u32 dst
			             )
{
	return ipsec_ah_encapsulate_common(inner_packet, payload_offset, payload_size, sa, IPSEC_AF_INET, &src, &dst);
}

int ipsec_ah_encapsulate_ipv6(void *inner_packet, int *payload_offset, int *payload_size,
						 sad_entry *sa, const __u8 *src, const __u8 *dst)
{
	return ipsec_ah_encapsulate_common(inner_packet, payload_offset, payload_size, sa, IPSEC_AF_INET6, src, dst);
}
