/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
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

/** @file esp.c
 *  @brief This module contains the Encapsulating Security Payload code
 *
 *  @author  Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  <B>IMPLEMENTATION:</B>
 * All functions work in-place (i.g. mainipulate directly the original
 * packet without copying any data). For the encapsulation routine,
 * the caller must ensure that space for the new IP and ESP header are
 * available in front of the packet:
 *
 *  <pre>
 *                              | pointer to packet header
 *     ________________________\/________________________________________________
 *    |          �       �      �                             � padd       � ev. |
 *    | Ethernet � newIP � ESP  �   original (inner) packet   � next-proto � ICV |
 *    |__________�_______�______�_____________________________�____________�_____|
 *    �                         �                             �                  � 
 *    �<-room for new headers-->�                             �<-   room tail  ->� 
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

#include "ipsec/aes_cbc.h"
#include "ipsec/sa.h"
#include "ipsec/des.h"
#include "ipsec/md5.h"
#include "ipsec/sha1.h"

#include "ipsec/esp.h"


static __u8 ipsec_esp_get_padding(int len, __u8 block_len);

static void ipsec_esp_finalize_packet(void *packet, int total_len, __u8 protocol)
{
	ipsec_packet_set_total_len(packet, total_len);
	ipsec_packet_set_protocol(packet, protocol);

	if(ipsec_packet_family(packet) == IPSEC_AF_INET)
	{
		((ipsec_ip_header *)packet)->chksum = 0;
		((ipsec_ip_header *)packet)->chksum = ipsec_ip_chksum(packet, sizeof(ipsec_ip_header));
	}
}

static void ipsec_esp_init_outer_ipv4(ipsec_ip_header *header, int total_len, __u32 src, __u32 dst)
{
	header->v_hl = 0x45;
	header->tos = 0;
	header->len = ipsec_htons((__u16)total_len);
	header->id = 1000;
	header->offset = 0;
	header->ttl = 64;
	header->protocol = IPSEC_PROTO_ESP;
	header->chksum = 0;
	header->src = src;
	header->dest = dst;
}

static void ipsec_esp_init_outer_ipv6(ipsec_ipv6_header *header, int total_len, const __u8 *src, const __u8 *dst)
{
	header->v_tc_fl = ipsec_htonl(6UL << 28);
	header->payload_len = ipsec_htons((__u16)(total_len - IPSEC_IPV6_HDR_SIZE));
	header->nexthdr = IPSEC_PROTO_ESP;
	header->hop_limit = 64;
	memcpy(header->src, src, 16);
	memcpy(header->dest, dst, 16);
}

static __u8 ipsec_esp_iv_size(__u8 enc_alg)
{
	switch(enc_alg)
	{
		case IPSEC_3DES:
			return IPSEC_ESP_3DES_IV_SIZE;
		case IPSEC_AES_CBC:
			return IPSEC_ESP_AES_CBC_IV_SIZE;
		default:
			return 0;
	}
}

static __u8 ipsec_esp_block_size(__u8 enc_alg)
{
	switch(enc_alg)
	{
		case IPSEC_3DES:
			return IPSEC_ESP_3DES_IV_SIZE;
		case IPSEC_AES_CBC:
			return IPSEC_AES_CBC_BLOCK_SIZE;
		default:
			return 0;
	}
}

static ipsec_status ipsec_esp_encrypt_payload(__u8 enc_alg, __u8 *payload, int payload_len, const __u8 *key, const __u8 *iv)
{
	if(enc_alg == IPSEC_3DES)
	{
		__u8 cbc_iv[IPSEC_ESP_3DES_IV_SIZE];

		memcpy(cbc_iv, iv, sizeof(cbc_iv));
		cipher_3des_cbc(payload, payload_len, (__u8 *)key, cbc_iv, DES_ENCRYPT, payload);
		return IPSEC_STATUS_SUCCESS;
	}

	if(enc_alg == IPSEC_AES_CBC)
	{
		return ipsec_aes_cbc_encrypt_buffer(payload, payload_len, key, iv);
	}

	return IPSEC_STATUS_NOT_IMPLEMENTED;
}

static ipsec_status ipsec_esp_decrypt_payload(__u8 enc_alg, __u8 *payload, int payload_len, const __u8 *key, const __u8 *iv)
{
	if(enc_alg == IPSEC_3DES)
	{
		__u8 cbc_iv[IPSEC_ESP_3DES_IV_SIZE];

		memcpy(cbc_iv, iv, sizeof(cbc_iv));
		cipher_3des_cbc(payload, payload_len, (__u8 *)key, cbc_iv, DES_DECRYPT, payload);
		return IPSEC_STATUS_SUCCESS;
	}

	if(enc_alg == IPSEC_AES_CBC)
	{
		return ipsec_aes_cbc_decrypt_buffer(payload, payload_len, key, iv);
	}

	return IPSEC_STATUS_NOT_IMPLEMENTED;
}

static ipsec_status ipsec_esp_encapsulate_common(void *packet, int *offset, int *len, sad_entry *sa,
									 __u8 outer_family, const void *src_addr, const void *dest_addr)
{
	#if !IPSEC_ENABLE_ESP
	(void)packet;
	(void)offset;
	(void)len;
	(void)sa;
	(void)outer_family;
	(void)src_addr;
	(void)dest_addr;
	return IPSEC_STATUS_NOT_IMPLEMENTED;
	#else
	ipsec_status ret_val = IPSEC_STATUS_NOT_INITIALIZED;
	int outer_header_len;
	int inner_len;
	int ip_header_len;
	int transport_len;
	#if IPSEC_ENABLE_TUNNEL_MODE
	int payload_offset;
	#endif
	int payload_len;
	__u8 iv_len;
	__u8 block_len;
	__u8 padd_len;
	__u8 *pos;
	__u8 padd;
	__u8 original_protocol;
	ipsec_esp_header *new_esp_header;
	unsigned char iv[IPSEC_ESP_MAX_IV_SIZE] = {0xD4, 0xDB, 0xAB, 0x9A, 0x9A, 0xDB, 0xD1, 0x94,
									0x4A, 0x7C, 0x13, 0xE2, 0x55, 0x99, 0x24, 0x6F};
	unsigned char digest[IPSEC_MAX_AUTHKEY_LEN];
	#if IPSEC_ENABLE_TUNNEL_MODE
	__u8 next_proto;
	#endif

	/*
	 * The ESP path shares one in-place implementation for transport and tunnel mode.
	 * Transport mode inserts ESP after the current IP header and encrypts only the
	 * original transport payload plus trailer. Tunnel mode encrypts the full inner IP
	 * packet and prepends a new outer IP header in the caller-provided headroom.
	 */
	outer_header_len = outer_family == IPSEC_AF_INET6 ? IPSEC_IPV6_HDR_SIZE : IPSEC_IPV4_HDR_SIZE;
	inner_len = ipsec_packet_total_len(packet);
	ip_header_len = ipsec_packet_header_len(packet);
	original_protocol = ipsec_packet_protocol(packet);
	iv_len = ipsec_esp_iv_size(sa->enc_alg);
	block_len = ipsec_esp_block_size(sa->enc_alg);

	if((iv_len == 0) || (block_len == 0))
	{
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	if(ipsec_packet_hop_limit(packet) == 0)
	{
		return IPSEC_STATUS_TTL_EXPIRED;
	}

	if(sa->mode == IPSEC_TRANSPORT)
	{
		#if !IPSEC_ENABLE_TRANSPORT_MODE
		return IPSEC_STATUS_NOT_IMPLEMENTED;
		#else
		transport_len = inner_len - ip_header_len;
		/* ESP transport mode keeps the existing IP header and protects only the payload. */
		padd_len = ipsec_esp_get_padding(transport_len + 2, block_len);
		new_esp_header = (ipsec_esp_header *)(((unsigned char *)packet) + ip_header_len);
		memmove(((unsigned char *)packet) + ip_header_len + IPSEC_ESP_HDR_SIZE + iv_len,
				((unsigned char *)packet) + ip_header_len,
				transport_len);

		pos = ((__u8 *)packet) + ip_header_len + IPSEC_ESP_HDR_SIZE + iv_len + transport_len;
		if(padd_len != 0)
		{
			padd = 1;
			while(padd <= padd_len)
			{
				*pos++ = padd++;
			}
		}

		*pos++ = padd_len;
		*pos = original_protocol;
		/* The encrypted region is payload + padding + pad length + next header. */
		payload_len = IPSEC_ESP_HDR_SIZE + iv_len + transport_len + padd_len + 2;

		ret_val = ipsec_esp_encrypt_payload(sa->enc_alg,
			(__u8 *)packet + ip_header_len + IPSEC_ESP_HDR_SIZE + iv_len,
			transport_len + padd_len + 2,
			sa->enckey,
			iv);
		if(ret_val != IPSEC_STATUS_SUCCESS)
		{
			return ret_val;
		}

		memcpy(((__u8 *)packet) + ip_header_len + IPSEC_ESP_HDR_SIZE, iv, iv_len);
		new_esp_header->spi = sa->spi;
		sa->sequence_number++;
		new_esp_header->sequence_number = ipsec_htonl(sa->sequence_number);

		if(sa->auth_alg != 0)
		{
			switch(sa->auth_alg) {
				case IPSEC_HMAC_MD5:
					hmac_md5((unsigned char *)new_esp_header, payload_len,
						 (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
					break;
				case IPSEC_HMAC_SHA1:
					hmac_sha1((unsigned char *)new_esp_header, payload_len,
						  (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
					break;
				default:
					return IPSEC_STATUS_FAILURE;
			}

			memcpy(((char *)new_esp_header) + payload_len, digest, IPSEC_AUTH_ICV);
			payload_len += IPSEC_AUTH_ICV;
		}

		ipsec_esp_finalize_packet(packet, ip_header_len + payload_len, IPSEC_PROTO_ESP);
		*offset = 0;
		*len = ip_header_len + payload_len;
		return IPSEC_STATUS_SUCCESS;
		#endif
	}
	else if(sa->mode != IPSEC_TUNNEL)
	{
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}
	#if !IPSEC_ENABLE_TUNNEL_MODE
	return IPSEC_STATUS_NOT_IMPLEMENTED;
	#else

	new_esp_header = (ipsec_esp_header *)(((char *)packet) - iv_len - IPSEC_ESP_HDR_SIZE);
	payload_offset = (((char *)packet) - (((char *)packet) - iv_len - IPSEC_ESP_HDR_SIZE - outer_header_len));

	/* Tunnel mode encrypts the complete inner packet and records its protocol in the trailer. */
	padd_len = ipsec_esp_get_padding(inner_len + 2, block_len);
	pos = ((__u8 *)packet) + inner_len;
	if(padd_len != 0)
	{
		padd = 1;
		while(padd <= padd_len)
		{
			*pos++ = padd++;
		}
	}

	*pos++ = padd_len;
	next_proto = ipsec_packet_family(packet) == IPSEC_AF_INET6 ? IPSEC_PROTO_IPV6 : IPSEC_PROTO_IPIP;
	*pos = next_proto;

	payload_len = inner_len + IPSEC_ESP_HDR_SIZE + iv_len + padd_len + 2;

	ret_val = ipsec_esp_encrypt_payload(sa->enc_alg,
		(__u8 *)packet,
		inner_len + padd_len + 2,
		sa->enckey,
		iv);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		return ret_val;
	}

	memcpy(((__u8 *)packet) - iv_len, iv, iv_len);

	new_esp_header->spi = sa->spi;
	sa->sequence_number++;
	new_esp_header->sequence_number = ipsec_htonl(sa->sequence_number);

	if(sa->auth_alg != 0)
	{
		switch(sa->auth_alg) {
			case IPSEC_HMAC_MD5:
				hmac_md5((unsigned char *)new_esp_header, payload_len,
					 (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			case IPSEC_HMAC_SHA1:
				hmac_sha1((unsigned char *)new_esp_header, payload_len,
					  (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			default:
				return IPSEC_STATUS_FAILURE;
		}

		memcpy(((char *)new_esp_header) + payload_len, digest, IPSEC_AUTH_ICV);
		payload_len += IPSEC_AUTH_ICV;
	}

	if(outer_family == IPSEC_AF_INET6)
	{
		ipsec_esp_init_outer_ipv6((ipsec_ipv6_header *)(((char *)packet) - iv_len - IPSEC_ESP_HDR_SIZE - outer_header_len),
								    payload_len + outer_header_len,
								    (const __u8 *)src_addr, (const __u8 *)dest_addr);
	}
	else
	{
		ipsec_ip_header *new_ip_header;
		new_ip_header = (ipsec_ip_header *)(((char *)packet) - iv_len - IPSEC_ESP_HDR_SIZE - outer_header_len);
		ipsec_esp_init_outer_ipv4(new_ip_header, payload_len + outer_header_len,
								  *((const __u32 *)src_addr), *((const __u32 *)dest_addr));
		new_ip_header->chksum = ipsec_ip_chksum(new_ip_header, sizeof(ipsec_ip_header));
	}

	*offset = payload_offset * (-1);
	*len = payload_len + outer_header_len;
	return IPSEC_STATUS_SUCCESS;
	#endif
	#endif
}



/**
 * Returns the number of padding needed for a certain ESP packet size 
 *
 * @param	len		the length of the packet
 * @return	the length of padding needed
 */
__u8 ipsec_esp_get_padding(int len, __u8 block_len)
{
	int padding ;

	for(padding = 0; padding < block_len; padding++)
		if(((len+padding) % block_len) == 0)
			break ;
	return padding ;
}

/**
 * Decapsulates an IP packet containing an ESP header.
 *
 * @param	packet 	pointer to the ESP header
 * @param 	offset	pointer to the offset which is passed back
 * @param 	len		pointer to the length of the decapsulated packet
 * @param 	sa		pointer to the SA
 * @return IPSEC_STATUS_SUCCESS 	if the packet could be decapsulated properly
 * @return IPSEC_STATUS_FAILURE		if the SA's authentication algorithm was invalid or if ICV comparison failed
 * @return IPSEC_STATUS_BAD_PACKET	if the decryption gave back a strange packet
 */
ipsec_status ipsec_esp_decapsulate(void *packet, int *offset, int *len, sad_entry *sa)
 {
	#if !IPSEC_ENABLE_ESP
	(void)packet;
	(void)offset;
	(void)len;
	(void)sa;
	return IPSEC_STATUS_NOT_IMPLEMENTED;
	#else
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;			/* by default, the return value is undefined */
	int				ip_header_len ;
	int					local_len ;
	int					payload_offset ;
	int					payload_len ;
	#if IPSEC_ENABLE_TUNNEL_MODE
	void				*new_ip_packet ;
	#endif
	esp_packet			*esp_header ;			
	char 				cbc_iv[IPSEC_ESP_MAX_IV_SIZE] ;
	unsigned char 		digest[IPSEC_MAX_AUTHKEY_LEN];
	int				packet_len;
	int				transport_len;
	__u8				pad_len;
	__u8				next_proto;
	__u8				iv_len;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_esp_decapsulate", 
				  ("packet=%p, *offset=%d, *len=%d sa=%p",
			      (void *)packet, *offset, *len, (void *)sa)
				 );
	
	ip_header_len = ipsec_packet_header_len(packet) ;
	esp_header = (esp_packet*)(((char*)packet)+ip_header_len) ; 
	payload_offset = ip_header_len + IPSEC_ESP_SPI_SIZE + IPSEC_ESP_SEQ_SIZE ;
	payload_len = ipsec_packet_total_len(packet) - ip_header_len - IPSEC_ESP_HDR_SIZE ;
	packet_len = ipsec_packet_total_len(packet);
	iv_len = ipsec_esp_iv_size(sa->enc_alg);

	if(iv_len == 0)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}


	if(sa->auth_alg != 0)
	{

		/*
		 * As with AH, replay handling is two-phase: cheap window rejection first,
		 * authenticated state update only after the ICV has been verified.
		 */
		ret_val = ipsec_check_replay_window(ipsec_ntohl(esp_header->sequence), sa->replay_last_seq, sa->replay_bitmap);
		if(ret_val != IPSEC_AUDIT_SUCCESS)
		{
			IPSEC_LOG_AUD("ipsec_esp_decapsulate", IPSEC_AUDIT_SEQ_MISMATCH, ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", sa->replay_last_seq, ipsec_ntohl(esp_header->sequence), IPSEC_SEQ_MAX_WINDOW) );
			return ret_val;
		}

		/* recalcualte ICV */
		switch(sa->auth_alg) {

		case IPSEC_HMAC_MD5: 
			hmac_md5((unsigned char *)esp_header, payload_len-IPSEC_AUTH_ICV+IPSEC_ESP_HDR_SIZE,
			         (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
			ret_val = IPSEC_STATUS_SUCCESS; 
			break;
		case IPSEC_HMAC_SHA1: 
			hmac_sha1((unsigned char *)esp_header, payload_len-IPSEC_AUTH_ICV+IPSEC_ESP_HDR_SIZE,
			          (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
			ret_val = IPSEC_STATUS_SUCCESS; 
			break;
		default:
			IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_FAILURE, ("unknown HASH algorithm for this ESP")) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
		}
		
		/* compare ICV */
		if(memcmp(((char*)esp_header)+IPSEC_ESP_HDR_SIZE+payload_len-IPSEC_AUTH_ICV, digest, IPSEC_AUTH_ICV) != 0) {
			IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_FAILURE, ("ESP ICV does not match")) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
		}

		/* reduce payload by ICV */
		payload_len -= IPSEC_AUTH_ICV ;

		/* post-ICV calculation anti-replay check (this call will update the SA sequence number window) */
		ret_val = ipsec_update_replay_window(ipsec_ntohl(esp_header->sequence), &sa->replay_last_seq, &sa->replay_bitmap);
		if(ret_val != IPSEC_AUDIT_SUCCESS)
		{
			IPSEC_LOG_AUD("ipsec_esp_decapsulate", IPSEC_AUDIT_SEQ_MISMATCH, ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", sa->replay_last_seq, ipsec_ntohl(esp_header->sequence), IPSEC_SEQ_MAX_WINDOW) );
			return ret_val;
		}

	}


	/*
	 * After authentication, decrypt in place. The IV stays in front of the ciphertext,
	 * so payload_offset points to SPI/SEQ/IV and the decrypted bytes start after the IV.
	 */
	memcpy(cbc_iv, ((char*)packet)+payload_offset, iv_len);
	ret_val = ipsec_esp_decrypt_payload(sa->enc_alg,
		(__u8 *)packet + payload_offset + iv_len,
		payload_len - iv_len,
		sa->enckey,
		(__u8 *)cbc_iv);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", ret_val) );
		return ret_val;
	}

	if(sa->mode == IPSEC_TRANSPORT)
	{
		#if !IPSEC_ENABLE_TRANSPORT_MODE
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
		#else
		transport_len = payload_len - iv_len;
		pad_len = *(((unsigned char *)packet) + payload_offset + iv_len + transport_len - 2);
		next_proto = *(((unsigned char *)packet) + payload_offset + iv_len + transport_len - 1);
		/* Strip IV, padding, pad length, and next-header trailer to reconstruct the original payload. */
		local_len = ip_header_len + transport_len - pad_len - 2;
		memmove(((unsigned char *)packet) + ip_header_len,
				((unsigned char *)packet) + payload_offset + iv_len,
				local_len - ip_header_len);
		ipsec_esp_finalize_packet(packet, local_len, next_proto);
		*offset = 0;
		*len = local_len;
		sa->sequence_number++ ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_SUCCESS) );
		return IPSEC_STATUS_SUCCESS;
		#endif
	}
	else if(sa->mode != IPSEC_TUNNEL)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}
	#if !IPSEC_ENABLE_TUNNEL_MODE
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
	return IPSEC_STATUS_NOT_IMPLEMENTED;
	#else

	*offset = payload_offset+iv_len ;

	/* Tunnel mode leaves a complete inner IP packet starting after SPI/SEQ/IV. */
	new_ip_packet = (void *)(((char*)packet) + payload_offset + iv_len) ;
	local_len = ipsec_packet_total_len(new_ip_packet) ;

	if( (local_len < IPSEC_MIN_IPHDR_SIZE) || (local_len > IPSEC_MTU))
	{
		IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_FAILURE, ("decapsulated strange packet")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_BAD_PACKET) );
		return IPSEC_STATUS_BAD_PACKET;
	}
	*len = local_len ;

	sa->sequence_number++ ;

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS;
	#endif
	#endif
 }

/**
 * Encapsulates an IP packet into an ESP packet which will again be added to an IP packet.
 * 
 * @param	packet		pointer to the IP packet 
 * @param 	offset		pointer to the offset which will point to the new encapsulated packet
 * @param 	len			pointer to the length of the new encapsulated packet
 * @param 	sa			pointer to the SA
 * @param 	src_addr	source IP address of the outer IP header
 * @param 	dest_addr	destination IP address of the outer IP header 
 * @return 	IPSEC_STATUS_SUCCESS		if the packet was properly encapsulated
 * @return 	IPSEC_STATUS_TTL_EXPIRED	if the TTL expired
 * @return  IPSEC_STATUS_FAILURE		if the SA contained a bad authentication algorithm
 */
 ipsec_status ipsec_esp_encapsulate(ipsec_ip_header *packet, int *offset, int *len, sad_entry *sa, __u32 src_addr, __u32 dest_addr)
 {
	return ipsec_esp_encapsulate_common(packet, offset, len, sa, IPSEC_AF_INET, &src_addr, &dest_addr);
 }

ipsec_status ipsec_esp_encapsulate_ipv6(void *packet, int *offset, int *len, sad_entry *sa, const __u8 *src_addr, const __u8 *dest_addr)
{
	return ipsec_esp_encapsulate_common(packet, offset, len, sa, IPSEC_AF_INET6, src_addr, dest_addr);
}

