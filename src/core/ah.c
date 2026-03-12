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
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;
	int outer_header_len;
	int inner_len;
	__u8 inner_family;
	ipsec_ah_header *new_ah_header;
	unsigned char digest[IPSEC_MAX_AUTHKEY_LEN];

	outer_header_len = outer_family == IPSEC_AF_INET6 ? IPSEC_IPV6_HDR_SIZE : IPSEC_IPV4_HDR_SIZE;
	inner_family = ipsec_packet_family(inner_packet);
	inner_len = ipsec_packet_total_len(inner_packet);
	new_ah_header = (ipsec_ah_header *)(((char *)inner_packet) - IPSEC_AUTH_ICV - IPSEC_AH_HDR_SIZE);

	if(ipsec_packet_hop_limit(inner_packet) == 0)
	{
		return IPSEC_STATUS_TTL_EXPIRED;
	}

	if(IPSEC_AUTH_ICV != 12)
	{
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	sa->sequence_number++;

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

	switch(sa->auth_alg) {
		case IPSEC_HMAC_MD5:
			hmac_md5((unsigned char *)(((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len),
				 inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len,
				 (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
			break;
		case IPSEC_HMAC_SHA1:
			hmac_sha1((unsigned char *)(((char *)inner_packet) - IPSEC_AH_HDR_SIZE - IPSEC_AUTH_ICV - outer_header_len),
				  inner_len + IPSEC_AH_HDR_SIZE + IPSEC_AUTH_ICV + outer_header_len,
				  (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
			break;
		default:
			return IPSEC_STATUS_FAILURE;
	}

	memcpy(new_ah_header->ah_data, digest, IPSEC_AUTH_ICV);

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
	int ret_val 	= IPSEC_STATUS_NOT_INITIALIZED;	/* by default, the return value is undefined */
	ipsec_ah_header *ah_header;
	int ah_len;
	int ah_offs;
	int packet_len;
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
	
 	/* zero all mutable fields prior to ICV calculation */
	/* mutuable fields according to RFC2402, 3.3.3.1.1.1. */
	ipsec_packet_zero_mutable_fields(outer_packet);

	/* backup 96bit HMAC before setting it to 0 */
	memcpy(orig_digest, ah_header->ah_data, IPSEC_AUTH_ICV);
	memset(((ipsec_ah_header *)((unsigned char *)outer_packet + ah_offs))->ah_data, '\0', IPSEC_AUTH_ICV);

	if(sa->mode != IPSEC_TUNNEL)
	{
		IPSEC_LOG_ERR("ipsec_ah_check", IPSEC_STATUS_NOT_IMPLEMENTED, ("Can't handle mode %d. Only mode %d (IPSEC_TUNNEL) is implemented.", sa->mode, IPSEC_TUNNEL) );
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
	
	*payload_offset = ah_offs + ah_len;
	*payload_size   = ipsec_packet_total_len((unsigned char *)outer_packet + ah_offs + ah_len);

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_ah_check", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
	return IPSEC_STATUS_SUCCESS;
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
