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

/** @file ipsec.c
 *  @brief embedded IPsec implementation (tunnel mode with manual keying only)
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 * The different IPsec functions are glued together at this place. All intercepted
 * inbound and outbound traffic which require IPsec processing is passed to this module. 
 * The packets are then processed processes according their SA.
 *
 *  <B>IMPLEMENTATION:</B>
 *  
 * For SA management code of the sa.c module was used. Then AH and ESP functionality out of
 * ah.c and esp.c was used to process the packets properly.
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */



#include "ipsec/debug.h"

#include "ipsec/ipsec.h"
#include "ipsec/util.h"
#include "ipsec/sa.h"
#include "ipsec/ah.h"
#include "ipsec/esp.h"

static int ipsec_mode_supported(__u8 mode)
{
	switch(mode)
	{
#if IPSEC_ENABLE_TUNNEL_MODE
		case IPSEC_TUNNEL:
			return 1;
#endif
#if IPSEC_ENABLE_TRANSPORT_MODE
		case IPSEC_TRANSPORT:
			return 1;
#endif
		default:
			return 0;
	}
}

static int ipsec_output_common(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size,
						   spd_entry *spd, __u8 outer_family, const void *src, const void *dst)
{
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;
	int total_len;

	if(packet == NULL)
	{
		return IPSEC_STATUS_BAD_PACKET;
	}

	total_len = ipsec_packet_total_len(packet);
	if(total_len > packet_size)
	{
		IPSEC_LOG_DBG("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED,
				("bad packet packet=%p, len=%d (must not be >%d bytes)", (void *)packet, total_len, packet_size) );
		return IPSEC_STATUS_BAD_PACKET;
	}

	if((spd == NULL) || (spd->sa == NULL))
	{
		IPSEC_LOG_DBG("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED, ("unable to generate dynamically an SA (IKE not implemented)") );
		IPSEC_LOG_AUD("ipsec_output", IPSEC_STATUS_NO_SA_FOUND, ("no SA or SPD defined")) ;
		return IPSEC_STATUS_NO_SA_FOUND;
	}

	if(!ipsec_mode_supported(spd->sa->mode))
	{
		IPSEC_LOG_ERR("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED, ("transmission mode %d is disabled at compile time", spd->sa->mode));
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	switch(spd->sa->protocol) {
#if IPSEC_ENABLE_AH
		case IPSEC_PROTO_AH:
			IPSEC_LOG_MSG("ipsec_output", ("have to encapsulate an AH packet")) ;
			if(outer_family == IPSEC_AF_INET6)
			{
				ret_val = ipsec_ah_encapsulate_ipv6(packet, payload_offset, payload_size, spd->sa,
											 (const __u8 *)src, (const __u8 *)dst);
			}
			else
			{
				ret_val = ipsec_ah_encapsulate((ipsec_ip_header *)packet, payload_offset, payload_size, spd->sa,
								   *((const __u32 *)src), *((const __u32 *)dst));
			}
			if(ret_val != IPSEC_STATUS_SUCCESS)
			{
				IPSEC_LOG_ERR("ipsec_output", ret_val, ("ipsec_ah_encapsulate() failed"));
			}
			break;
#endif

#if IPSEC_ENABLE_ESP
		case IPSEC_PROTO_ESP:
			IPSEC_LOG_MSG("ipsec_output", ("have to encapsulate an ESP packet")) ;
			if(outer_family == IPSEC_AF_INET6)
			{
				ret_val = ipsec_esp_encapsulate_ipv6(packet, payload_offset, payload_size, spd->sa,
											  (const __u8 *)src, (const __u8 *)dst);
			}
			else
			{
				ret_val = ipsec_esp_encapsulate((ipsec_ip_header *)packet, payload_offset, payload_size, spd->sa,
									 *((const __u32 *)src), *((const __u32 *)dst));
			}
			if(ret_val != IPSEC_STATUS_SUCCESS)
			{
				IPSEC_LOG_ERR("ipsec_output", ret_val, ("ipsec_esp_encapsulate() failed"));
			}
			break;
#endif

		default:
			ret_val = IPSEC_STATUS_NOT_IMPLEMENTED;
			IPSEC_LOG_ERR("ipsec_output", ret_val, ("protocol '%d' is disabled at compile time or unsupported", spd->sa->protocol));
	}

	return ret_val;
}



/**
 * IPsec input processing
 *
 * This function is called by the ipsec device driver when a packet arrives having AH or ESP in the 
 * protocol field. A SA lookup gets the appropriate SA which is then passed to the packet processing 
 * funciton ipsec_ah_check() or ipsec_esp_decapsulate(). After successfully processing an IPsec packet
 * an check together with an SPD lookup verifies if the packet was processed acording the right SA.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  databases      Collection of all security policy databases for the active IPsec device 
 * @return int 			  return status code
 */
int ipsec_input(unsigned char *packet, int packet_size, 
                int *payload_offset, int *payload_size, 
				db_set_netif *databases)
{
	int ret_val 	= IPSEC_STATUS_NOT_INITIALIZED;	/* by default, the return value is undefined  */
	int dummy   	= packet_size; 					/* dummy operation to avoid compiler warnings */
	sad_entry 		*sa ;
	spd_entry		*spd ;
	void			*inner_ip ;
	ipsec_ip_address dest_addr;
	__u32			spi ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_input", 
				  ("*packet=%p, packet_size=%d, len=%u, *payload_offset=%d, *payload_size=%d databases=%p",
			      (void *)packet, packet_size, (int)*payload_offset, (int)*payload_size, (void *)databases)
				 );

	if(packet == NULL)
	{
		return IPSEC_STATUS_BAD_PACKET;
	}

	IPSEC_DUMP_BUFFER(" INBOUND ESP or AH:", packet, 0, packet_size);
	
	spi = ipsec_sad_get_spi(packet) ;
	ipsec_packet_get_addresses(packet, NULL, &dest_addr);
	sa = ipsec_sad_lookup_addr(&dest_addr, ipsec_packet_protocol(packet), spi, &databases->inbound_sad) ;

	if(sa == NULL)
	{
		IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_FAILURE, ("no matching SA found")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_FAILURE) );
		return IPSEC_STATUS_FAILURE;
	}

	if(!ipsec_mode_supported(sa->mode)) 
	{
		IPSEC_LOG_ERR("ipsec_input", IPSEC_STATUS_NOT_IMPLEMENTED, ("transmission mode %d is disabled at compile time", sa->mode) );
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	#if IPSEC_ENABLE_AH
	if(sa->protocol == IPSEC_PROTO_AH)
	{
		ret_val = ipsec_ah_check(packet, payload_offset, payload_size, sa);
		if(ret_val != IPSEC_STATUS_SUCCESS) 
		{
			IPSEC_LOG_ERR("ipsec_input", ret_val, ("ah_packet_check() failed") );
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", ret_val) );
			return ret_val;
		}

	}
	else
	#endif
	#if IPSEC_ENABLE_ESP
	if (sa->protocol == IPSEC_PROTO_ESP)
	{
		ret_val = ipsec_esp_decapsulate(packet, payload_offset, payload_size, sa);
		if(ret_val != IPSEC_STATUS_SUCCESS) 
		{
			IPSEC_LOG_ERR("ipsec_input", ret_val, ("ipsec_esp_decapsulate() failed") );
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", ret_val) );
			return ret_val;
		}

	}
	else
	#endif
	{
		IPSEC_LOG_ERR("ipsec_input", IPSEC_STATUS_NOT_IMPLEMENTED, ("protocol %d is disabled at compile time or unsupported", sa->protocol) );
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", IPSEC_STATUS_NOT_IMPLEMENTED) );
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	inner_ip = (void *)(packet + *payload_offset) ;

	spd = ipsec_spd_lookup(inner_ip, &databases->inbound_spd) ;
	if(spd == NULL)
	{
		IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_FAILURE, ("no matching SPD found")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", IPSEC_STATUS_FAILURE) );
		return IPSEC_STATUS_FAILURE;
	}
	
	if(spd->policy == POLICY_APPLY)
	{
		if(spd->sa != sa)
		{
			IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_SPI_MISMATCH, ("SPI mismatch") );
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_AUDIT_SPI_MISMATCH) );
			return IPSEC_STATUS_FAILURE;
		}
	}
	else
	{
			IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_POLICY_MISMATCH, ("matching SPD does not permit IPsec processing") );
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS;
}


/**
 *  IPsec output processing
 *
 * This function is called when outbound packets need IPsec processing. Depending the SA, passed via
 * the SPD entry ipsec_ah_check() and ipsec_esp_encapsulate() is called to encapsulate the packet in a
 * IPsec header.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  src            IP address of the local tunnel start point (external IP address)
 * @param  dst            IP address of the remote tunnel end point (external IP address)
 * @param  spd            pointer to security policy database where the rules for IPsec processing are stored
 * @return int 			  return status code
 */
int ipsec_output(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size,
                 __u32 src, __u32 dst, spd_entry *spd)
{
	int ret_val;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_output", 
				  ("*packet=%p, packet_size=%d, len=%u, *payload_offset=%d, *payload_size=%d src=%lx dst=%lx *spd=%p",
			      (void *)packet, packet_size, *payload_offset, *payload_size, (__u32) src, (__u32) dst, (void *)spd)
				 );

	ret_val = ipsec_output_common(packet, packet_size, payload_offset, payload_size, spd, IPSEC_AF_INET, &src, &dst);

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("ret_val=%d", ret_val) );
	return ret_val;
}

int ipsec_output_ipv6(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size,
					 const __u8 *src, const __u8 *dst, spd_entry *spd)
{
	int ret_val;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
	              "ipsec_output_ipv6",
				  ("*packet=%p, packet_size=%d, *payload_offset=%d, *payload_size=%d src=%p dst=%p *spd=%p",
			      (void *)packet, packet_size, *payload_offset, *payload_size, (const void *)src, (const void *)dst, (void *)spd)
				 );

	ret_val = ipsec_output_common(packet, packet_size, payload_offset, payload_size, spd, IPSEC_AF_INET6, src, dst);

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output_ipv6", ("ret_val=%d", ret_val) );
	return ret_val;
}


