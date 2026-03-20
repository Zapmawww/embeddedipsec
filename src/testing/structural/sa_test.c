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

/** @file sa_test.c
 *  @brief Test functions for Security Association Database
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 *  <B>OUTLINE:</B>
 *
 *  This file contains test functions used to verify the SA code.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  There are no implementation hints to be mentioned.
 *
 *  <B>NOTES:</B>
 *
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>

#include "ipsec/util.h"
#include "ipsec/debug.h"
#include "testing/structural/structural_test.h"

#include "ipsec/sa.h"

sad_entry inbound_sad_test[IPSEC_MAX_SAD_ENTRIES] = {
	{ SAD_ENTRY(	192,168,1,1, 255,255,255,255, 
				0x1001, 
				IPSEC_PROTO_ESP, IPSEC_TUNNEL, 
				IPSEC_3DES, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45 , 0x67, 0x01, 0x23, 0x45, 0x67, 
				0,  
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) },

	{ SAD_ENTRY(	192,168,1,2, 255,255,255,255, 
				0x1002, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45 , 0x67, 0x01, 0x23, 0x45, 0x67,  
				IPSEC_HMAC_MD5,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0) },

	{ SAD_ENTRY(	192,168,156,189, 255,255,255,255, 
				0x0010002, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45 , 0x67, 0x01, 0x23, 0x45, 0x67, 
				IPSEC_HMAC_SHA1,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0) }
} ;

/* SPD configuration data */
spd_entry inbound_spd_test[IPSEC_MAX_SAD_ENTRIES] = {
/*            source                            destination                       protocol          ports         policy          SA pointer 
 *            address          network          address          network                            src    dest                              */
{ SPD_ENTRY(  204,152,189,116, 255,255,255,0,   147,87,70,105,   255,255,255,255, IPSEC_PROTO_TCP,  21,    0,     POLICY_DISCARD, 0)},
{ SPD_ENTRY(  147,87,70,105,   255,255,255,255, 204,152,189,116, 255,255,255,255, IPSEC_PROTO_TCP,  0,     21,    POLICY_APPLY,   0)},
{ SPD_ENTRY(  147,87,70,250,   255,255,255,0,   255,255,255,255, 255,255,255,255, IPSEC_PROTO_UDP,  0,     0,     POLICY_APPLY,   0)},
{ SPD_ENTRY(  192,168,1,0,     255,255,255,0,   192,168,1,3,     255,255,255,255, IPSEC_PROTO_AH,   0,     0,     POLICY_APPLY,   0)},
{ SPD_ENTRY(  192,168,1,40,    255,255,255,255, 192,168,1,3,     255,255,255,255, IPSEC_PROTO_ESP,  0,     0,     POLICY_APPLY,   0)},
{ SPD_ENTRY(  0,0,0,0,         0,0,0,0,         0,0,0,0,         0,0,0,0,         0,                0,     0,     POLICY_BYPASS,  0)}
} ;

/* outbound configurations */

/* SAD configuartion data */
sad_entry outbound_sad_test[IPSEC_MAX_SAD_ENTRIES] = {
	{ SAD_ENTRY(	192,168,156,189, 255,255,255,255, 
				0x100000, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				IPSEC_3DES, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45 , 0x67, 0x01, 0x23, 0x45, 0x67, 
				IPSEC_HMAC_SHA1,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0) },

	{ SAD_ENTRY(	192,168,156,189, 255,255,255,255, 
				0x100000, 
				IPSEC_PROTO_ESP, IPSEC_TUNNEL, 
				IPSEC_3DES, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45 , 0x67, 0x01, 0x23, 0x45, 0x67, 
				IPSEC_HMAC_SHA1,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0) },

	{ SAD_ENTRY(	192,168,156,189, 255,255,255,255, 
				0x100000, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45 , 0x67, 0x01, 0x23, 0x45, 0x67, 
				IPSEC_HMAC_SHA1,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0) }
} ;

/* SPD configuration data */
spd_entry outbound_spd_test[IPSEC_MAX_SPD_ENTRIES] = {
/*            source                            destination                       protocol          ports         policy          SA pointer 
 *            address          network          address          network                            src    dest                              */
{ SPD_ENTRY(  192,168,1,1,     255,255,255,255, 192,168,1,3,     255,255,255,255, IPSEC_PROTO_ICMP, 0,     0,     POLICY_APPLY,   0)},
{ SPD_ENTRY(  192,168,1,2,     255,255,255,255, 192,168,1,3,     255,255,255,255, 0,                0,     80,    POLICY_DISCARD, 0)},
{ SPD_ENTRY(  192,168,1,2,     255,255,255,255, 192,168,1,3,     255,255,255,255, 0,                0,     0,     POLICY_BYPASS,  0)},
{ SPD_ENTRY(  0,0,0,0,         0,0,0,0,         0,0,0,0,         0,0,0,0,         0,                0,     0,     POLICY_BYPASS,  0)}
} ;

spd_entry outbound_spd[IPSEC_MAX_SPD_ENTRIES] ;
spd_entry inbound_spd[IPSEC_MAX_SPD_ENTRIES] ;

sad_entry outbound_sad[IPSEC_MAX_SAD_ENTRIES] ;
sad_entry inbound_sad[IPSEC_MAX_SAD_ENTRIES] ;

/* ip header packet data */

unsigned char ip_ftp_1[70] =
{
    0x45, 0x00, 0x00, 0x46, 0x8E, 0xF2, 0x40, 0x00, 0x31, 0x06, 0x56, 0xF2, 0xCC, 0x98, 0xBD, 0x74,
    0x93, 0x57, 0x46, 0x69, 0x00, 0x15, 0x11, 0xEF, 0x38, 0x57, 0xC8, 0x7F, 0xEC, 0x0F, 0x03, 0x14,
    0x50, 0x18, 0x16, 0xD0, 0x76, 0x2A, 0x00, 0x00, 0x32, 0x30, 0x30, 0x20, 0x50, 0x4F, 0x52, 0x54,
    0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73,
    0x66, 0x75, 0x6C, 0x2E, 0x0D, 0x0A,
} ;

unsigned char ip_ftp_2[67] =
{
    0x45, 0x00, 0x00, 0x43, 0xB6, 0x8F, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0x93, 0x57, 0x46, 0x69,
    0xCC, 0x98, 0xBD, 0x74, 0x11, 0xEF, 0x00, 0x15, 0xEC, 0x0F, 0x02, 0xF9, 0x38, 0x57, 0xC8, 0x7F,
    0x50, 0x18, 0xFF, 0x62, 0x64, 0x03, 0x00, 0x00, 0x50, 0x4F, 0x52, 0x54, 0x20, 0x31, 0x34, 0x37,
    0x2C, 0x38, 0x37, 0x2C, 0x37, 0x30, 0x2C, 0x31, 0x30, 0x35, 0x2C, 0x31, 0x37, 0x2C, 0x32, 0x34,
    0x30, 0x0D, 0x0A,
} ;

unsigned char ip_rip[28] =
{
    0x45, 0xC0, 0x02, 0x14, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, 0xDB, 0xC8, 0x93, 0x57, 0x46, 0xFA,
    0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x08, 0x02, 0x08, 0x02, 0x00, 0x96, 0x98,
} ;

unsigned char ip_ah[20] =
{
    0x45, 0x00, 0x00, 0x68, 0x79, 0x9C, 0x00, 0x00, 0x40, 0x33, 0x7D, 0x4B, 0xC0, 0xA8, 0x01, 0x28,
    0xC0, 0xA8, 0x01, 0x03,
} ;

unsigned char ip_esp[20] =
{
    0x45, 0x00, 0x00, 0x64, 0x79, 0x30, 0x00, 0x00, 0x40, 0x32, 0x7D, 0xBC, 0xC0, 0xA8, 0x01, 0x28,
    0xC0, 0xA8, 0x01, 0x03,
} ;

unsigned char ip_def[70] =
{
    0x45, 0x00, 0x00, 0x46, 0x8E, 0xF2, 0x40, 0x00, 0x31, 0x06, 0x56, 0xF2, 0xCA, 0x92, 0xB0, 0x74,
    0x93, 0x57, 0x46, 0x69, 0x00, 0x15, 0x11, 0xEF, 0x38, 0x57, 0xC8, 0x7F, 0xEC, 0x0F, 0x03, 0x14,
    0x50, 0x18, 0x16, 0xD0, 0x76, 0x2A, 0x00, 0x00, 0x32, 0x30, 0x30, 0x20, 0x50, 0x4F, 0x52, 0x54,
    0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73,
    0x66, 0x75, 0x6C, 0x2E, 0x0D, 0x0A,
} ;

unsigned char esp_hdr[32] =
{
    0x45, 0x00, 0x00, 0x64, 0x79, 0x30, 0x00, 0x00, 0x40, 0x32, 0x7D, 0xBC, 0xC0, 0xA8, 0x01, 0x28,
    0xC0, 0xA8, 0x01, 0x03, 0x00, 0x00, 0x10, 0x06, 0x00, 0x00, 0x00, 0x01, 0x87, 0xC5, 0xBA, 0x8C,
} ;

unsigned char ah_hdr[48] =
{
    0x45, 0x00, 0x00, 0x68, 0x79, 0x9C, 0x00, 0x00, 0x40, 0x33, 0x7D, 0x4B, 0xC0, 0xA8, 0x01, 0x28,
    0xC0, 0xA8, 0x01, 0x03, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x09, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x2F, 0x1D, 0xE9, 0xEE, 0x8B, 0x41, 0x26, 0x44, 0x51, 0xCC, 0x8D, 0x45, 0x00, 0x00, 0x3C,
} ;

#define MAX_IP_ADD_LENGTH (15)

static spd_entry *find_default_bypass_for_family(spd_table *table, __u8 addr_family)
{
	spd_entry *entry;

	for(entry = table->first; entry != NULL; entry = entry->next)
	{
		if((entry->policy != POLICY_BYPASS) || (entry->protocol != 0) || (entry->src_port != 0) || (entry->dest_port != 0))
		{
			continue;
		}

		if(addr_family == IPSEC_AF_INET6)
		{
			static const __u8 zero_ipv6[16] = { 0 };

			if((entry->addr_family == IPSEC_AF_INET6) &&
			   (memcmp(entry->src_ipv6, zero_ipv6, sizeof(zero_ipv6)) == 0) &&
			   (memcmp(entry->src_netaddr_ipv6, zero_ipv6, sizeof(zero_ipv6)) == 0) &&
			   (memcmp(entry->dest_ipv6, zero_ipv6, sizeof(zero_ipv6)) == 0) &&
			   (memcmp(entry->dest_netaddr_ipv6, zero_ipv6, sizeof(zero_ipv6)) == 0))
			{
				return entry;
			}
			continue;
		}

		if((entry->addr_family != IPSEC_AF_INET6) &&
		   (entry->src == 0) && (entry->src_netaddr == 0) &&
		   (entry->dest == 0) && (entry->dest_netaddr == 0))
		{
			return entry;
		}
	}

	return NULL;
}


/**
 * Check if the SPD initialization works correctly.
 * 16 tests are performed here.
 */
int test_spd_init(void)
{
	int 			local_error_count = 0 ;
	int				entry_count ;
	spd_entry		*spd ;
	sad_entry		*sad ;
	db_set_netif	*databases ;

	/* init the config data */
	memset(inbound_spd, 0, sizeof(inbound_spd)) ;
	memset(outbound_spd, 0, sizeof(outbound_spd)) ;
	memset(inbound_sad, 0, sizeof(inbound_sad)) ;
	memset(outbound_sad, 0, sizeof(outbound_sad)) ;

	memcpy(inbound_spd, inbound_spd_test, sizeof(inbound_spd_test)) ;
	memcpy(outbound_spd, outbound_spd_test, sizeof(outbound_spd_test)) ;
	memcpy(inbound_sad, inbound_sad_test, sizeof(inbound_sad_test)) ;
	memcpy(outbound_sad, outbound_sad_test, sizeof(outbound_sad_test)) ;

	/* init the table */
	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad) ;
	if(databases == NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_inbound: unable to initialize the databases")) ;
	}

	/* now we test for each configuration table, if it was linked properly */

	/* check if linking was done properly for SPD inbound */
	for(entry_count = 1, spd = databases->inbound_spd.first; spd->next != NULL; spd = spd->next, entry_count++) ;

	if(entry_count != 6)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_inbound: did not link all entries properly")) ;
	}
	if(spd != databases->inbound_spd.last)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_inbound: did reach end of linked list")) ;
	}
	if(spd != &databases->inbound_spd.table[5])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_inbound: linked list does not end at last entry")) ;
	}
	if(databases->inbound_spd.first != &databases->inbound_spd.table[0])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_inbound: linked list does not start at first entry")) ;
	}

	/* check if linking was done properly for SPD outbound */
	for(entry_count = 1, spd = databases->outbound_spd.first; spd->next != NULL; spd = spd->next, entry_count++) ;

	if(entry_count != 4)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_outbound: did not link all entries properly")) ;
	}
	if(spd != databases->outbound_spd.last)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_outbound: did reach end of linked list")) ;
	}
	if(spd != &databases->outbound_spd.table[3])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_outbound: linked list does not end at last entry")) ;
	}
	if(databases->outbound_spd.first != &databases->outbound_spd.table[0])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("spd_outbound: linked list does not start at first entry")) ;
	}

	/* check if linking was done properly for SAD inbound */
	for(entry_count = 1, sad = databases->inbound_sad.first; sad->next != NULL; sad = sad->next, entry_count++) ;

	if(entry_count != 3)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_inbound: did not link all entries properly")) ;
	}
	if(sad != databases->inbound_sad.last)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_inbound: did reach end of linked list")) ;
	}
	if(sad != &databases->inbound_sad.table[2])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_inbound: linked list does not end at last entry")) ;
	}
	if(databases->inbound_sad.first != &databases->inbound_sad.table[0])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_inbound: linked list does not start at first entry")) ;
	}

	/* check if linking was done properly for SAD outbound */
	for(entry_count = 1, sad = databases->outbound_sad.first; sad->next != NULL; sad = sad->next, entry_count++) ;

	if(entry_count != 3)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_init", "FAILURE", ("sad_outbound: did not link all entries properly")) ;
	}
	if(sad != databases->outbound_sad.last)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_outbound: did reach end of linked list")) ;
	}
	if(sad != &databases->outbound_sad.table[2])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_outbound: linked list does not end at last entry")) ;
	}
	if(databases->outbound_sad.first != &databases->outbound_sad.table[0])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_init", "FAILURE", ("sad_outbound: linked list does not start at first entry")) ;
	}

	if(databases)
		ipsec_spd_release_dbs(databases) ;

	return local_error_count ;
}

int test_spd_init_dbs(void)
{
	int local_error_count = 0;
	db_set_netif databases = { 0 };
	spd_entry inbound_spd_storage[IPSEC_MAX_SPD_ENTRIES] = { EMPTY_SPD_ENTRY };
	spd_entry outbound_spd_storage[IPSEC_MAX_SPD_ENTRIES] = { EMPTY_SPD_ENTRY };
	sad_entry inbound_sad_storage[IPSEC_MAX_SAD_ENTRIES] = { EMPTY_SAD_ENTRY };
	sad_entry outbound_sad_storage[IPSEC_MAX_SAD_ENTRIES] = { EMPTY_SAD_ENTRY };
	db_set_netif *initialized;

	inbound_spd_storage[0].use_flag = IPSEC_USED;
	inbound_spd_storage[2].use_flag = IPSEC_USED;
	outbound_spd_storage[1].use_flag = IPSEC_USED;
	inbound_sad_storage[1].use_flag = IPSEC_USED;
	outbound_sad_storage[0].use_flag = IPSEC_USED;
	outbound_sad_storage[3].use_flag = IPSEC_USED;

	initialized = ipsec_spd_init_dbs(&databases,
							 inbound_spd_storage,
							 outbound_spd_storage,
							 inbound_sad_storage,
							 outbound_sad_storage);
	if(initialized != &databases)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("ipsec_spd_init_dbs() did not return the caller-owned database set"));
	}

	if(databases.use_flag != IPSEC_USED)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("database set was not marked in use"));
	}

	if((databases.inbound_spd.size != IPSEC_MAX_SPD_ENTRIES) ||
	   (databases.outbound_spd.size != IPSEC_MAX_SPD_ENTRIES))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("SPD table sizes were not initialized"));
	}

	if((databases.inbound_spd.first != &inbound_spd_storage[0]) ||
	   (databases.inbound_spd.last != &inbound_spd_storage[2]))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("inbound SPD links were not rebuilt correctly"));
	}

	if((inbound_spd_storage[0].next != &inbound_spd_storage[2]) ||
	   (inbound_spd_storage[2].prev != &inbound_spd_storage[0]))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("sparse inbound SPD entries were not linked together"));
	}

	if((databases.outbound_spd.first != &outbound_spd_storage[1]) ||
	   (databases.outbound_spd.last != &outbound_spd_storage[1]))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("single outbound SPD entry was not linked correctly"));
	}

	if((databases.inbound_sad.first != &inbound_sad_storage[1]) ||
	   (databases.inbound_sad.last != &inbound_sad_storage[1]) ||
	   (databases.outbound_sad.first != &outbound_sad_storage[0]) ||
	   (databases.outbound_sad.last != &outbound_sad_storage[3]))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("SAD links were not rebuilt correctly"));
	}

	if(ipsec_spd_release_dbs(&databases) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("ipsec_spd_release_dbs() did not succeed on caller-owned storage"));
	}

	if((databases.use_flag != IPSEC_FREE) ||
	   (databases.inbound_spd.table != NULL) ||
	   (databases.outbound_spd.table != NULL) ||
	   (databases.inbound_sad.table != NULL) ||
	   (databases.outbound_sad.table != NULL) ||
	   (databases.inbound_spd.size != 0) ||
	   (databases.outbound_spd.size != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_init_dbs", "FAILURE", ("ipsec_spd_release_dbs() did not clear the database set"));
	}

	return local_error_count;
}

/**
 * Check if SPD lookup for free entries works.
 * 4 tests are performed here.
 */
int test_spd_get_free(void)
{
	int 			index ;
	int 			local_error_count = 0 ;
	spd_entry 		*free_entry ;
	db_set_netif	*databases ;

	/* init the config data */
	memset(inbound_spd, 0, sizeof(inbound_spd)) ;

	/* init the table */
	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad) ;
	if(databases == NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_get_free", "FAILURE", ("spd_inbound: unable to initialize the databases")) ;
	}

	/* set all entries to FREE */
	for(index = 0; index < IPSEC_MAX_SPD_ENTRIES; index++)
	{
		databases->inbound_spd.table[index].use_flag = IPSEC_FREE ;
	}

	/* test if we get the first entry out of the datapool */
	free_entry = ipsec_spd_get_free(&databases->inbound_spd) ;
	if (free_entry != inbound_spd)
	{
			local_error_count++ ;
			IPSEC_LOG_TST("test_spd_get_first", "FAILURE", ("unable to get the first entry from SPD data pool")) ;
	}

	/* lets mark two entries as used */
	inbound_spd[0].use_flag = IPSEC_USED ;
	inbound_spd[2].use_flag = IPSEC_USED ;
		
	/* test if we get the right entry */
	free_entry = ipsec_spd_get_free(&databases->inbound_spd) ;
	if (free_entry != &inbound_spd[1])
	{
			local_error_count++ ;
			IPSEC_LOG_TST("test_spd_get_first", "FAILURE", ("unable to get the right free entry")) ;
	}

	/* lets mark all entries as used, EXCEPT the last one */
	for(index = 0; index < IPSEC_MAX_SPD_ENTRIES-1; index++)
	{
		inbound_spd[index].use_flag = IPSEC_USED ;
	}
	
	/* check if we got the last entry out of the pool */
	free_entry = ipsec_spd_get_free(&databases->inbound_spd) ;
	if (free_entry != &inbound_spd[IPSEC_MAX_SPD_ENTRIES-1])
	{
			local_error_count++ ;
			IPSEC_LOG_TST("test_spd_get_first", "FAILURE", ("unable to get the last free entry")) ;
	}

	/* mark also the last free entry */
	inbound_spd[IPSEC_MAX_SPD_ENTRIES-1].use_flag = IPSEC_USED ; 

	/* now there is no free entry */
	free_entry = ipsec_spd_get_free(&databases->inbound_spd) ;
	if (free_entry != NULL)
	{
			local_error_count++ ;
			IPSEC_LOG_TST("test_spd_get_first", "FAILURE", ("got a pointer but should have received NULL")) ;
	}

	if(databases)
		ipsec_spd_release_dbs(databases) ;

	return local_error_count ;
}


/**
 * Test adding of SPD entries
 * 5 tests are performed here
 */
int test_spd_add(void)
{
	spd_entry 		*entry ;
	int				local_error_count = 0;
	db_set_netif	*databases ;

	if(IPSEC_MAX_SPD_ENTRIES < 10)
		IPSEC_LOG_TST("test_spd_add", "WARNING", ("IPSEC_MAX_SA_ENTRIES may be too small for running test properly")) ;

	/* init the config data */
	memset(inbound_spd, 0, sizeof(inbound_spd)) ;
	memset(outbound_spd, 0, sizeof(outbound_spd)) ;
	memset(inbound_sad, 0, sizeof(inbound_sad)) ;
	memset(outbound_sad, 0, sizeof(outbound_sad)) ;

	memcpy(inbound_spd, inbound_spd_test, sizeof(inbound_spd_test)) ;
	memcpy(outbound_spd, outbound_spd_test, sizeof(outbound_spd_test)) ;
	memcpy(inbound_sad, inbound_sad_test, sizeof(inbound_sad_test)) ;
	memcpy(outbound_sad, outbound_sad_test, sizeof(outbound_sad_test)) ;

	/* init the table */
	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad) ;
	if(databases == NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_add", "FAILURE", ("spd_inbound: unable to initialize the databases")) ;
	}

	/* add first entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.40"),		
							ipsec_inet_addr("255.255.255.255"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),						
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_add", "FAILURE", ("1st entry could not be added")) ;
	}

	/* add second entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.0"),	
							ipsec_inet_addr("255.255.255.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),	
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_add", "FAILURE", ("2nd entry could not be added")) ;
	}

	/* add third entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("147.87.0.0"),		
							ipsec_inet_addr("255.255.0.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),	
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_add", "FAILURE", ("3th entry could not be added")) ;
	}

	/* add 4th entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.0"),		
							ipsec_inet_addr("255.255.255.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),	
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_add", "FAILURE", ("4th entry could not be added")) ;
	}

	/* this entry is too much */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.0"),		
							ipsec_inet_addr("255.255.255.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_add", "FAILURE", ("5th entry should not have been added")) ;
	}

	if(databases)
		ipsec_spd_release_dbs(databases) ;

	return local_error_count ;	
}


/**
 * Test removing of SPD entries
 * 10 tests are performed here
 */
int test_spd_del(void)
{
	ipsec_status 	status ;
	spd_entry 		*test_pointer, *entry ;
	int				local_error_count = 0 ;

	db_set_netif	*databases ;

	if(IPSEC_MAX_SPD_ENTRIES < 10)
		IPSEC_LOG_TST("test_spd_del", "WARNING", ("IPSEC_MAX_SA_ENTRIES may be too small for running test properly")) ;

	/* init the config data */
	memset(inbound_spd, 0, sizeof(inbound_spd)) ;
	memset(outbound_spd, 0, sizeof(outbound_spd)) ;
	memset(inbound_sad, 0, sizeof(inbound_sad)) ;
	memset(outbound_sad, 0, sizeof(outbound_sad)) ;

	memcpy(inbound_spd, inbound_spd_test, sizeof(inbound_spd_test)) ;
	memcpy(outbound_spd, outbound_spd_test, sizeof(outbound_spd_test)) ;
	memcpy(inbound_sad, inbound_sad_test, sizeof(inbound_sad_test)) ;
	memcpy(outbound_sad, outbound_sad_test, sizeof(outbound_sad_test)) ;

	/* init the table */
	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad) ;
	if(databases == NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("spd_inbound: unable to initialize the databases")) ;
	}

	/* add first entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.40"),		
							ipsec_inet_addr("255.255.255.255"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),						
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("1st entry could not be added")) ;
	}

	/* add second entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.0"),	
							ipsec_inet_addr("255.255.255.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),	
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("2nd entry could not be added")) ;
	}

	/* add third entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("147.87.0.0"),		
							ipsec_inet_addr("255.255.0.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),	
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("3rd entry could not be added")) ;
	}

	/* add 4th entry */
	entry = ipsec_spd_add( 	ipsec_inet_addr("192.168.1.0"),		
							ipsec_inet_addr("255.255.255.0"),
							ipsec_inet_addr("192.168.1.3"),
							ipsec_inet_addr("255.255.255.255"),
							0x06,							
							ipsec_htons(0),						
							ipsec_htons(80),	
							POLICY_APPLY,
							&databases->inbound_spd)	;			
	if(!entry)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("4th entry could not be added")) ;
	}

	/* try to remove with an invalid pointer */
	test_pointer = databases->inbound_spd.table -1 ;
	status = ipsec_spd_del(test_pointer, &databases->inbound_spd) ;
	if(status == IPSEC_STATUS_SUCCESS)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("was able to delete an SPD entry which does not exitst")) ;
	}

	/* try to remove with an invalid pointer */
	test_pointer = databases->inbound_spd.table + 1000 ;
	status = ipsec_spd_del(test_pointer, &databases->inbound_spd) ;
	if(status == IPSEC_STATUS_SUCCESS)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("was able to delete an SPD entry which does not exist")) ;
	}

	/* remove 2nd entry */
	test_pointer = databases->inbound_spd.table + 1 ;
	status = ipsec_spd_del(test_pointer, &databases->inbound_spd) ;
	if(status == IPSEC_STATUS_FAILURE)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("was not able to remove 2nd SPD entry")) ;
	}

	/* remove 4nd entry */
	test_pointer = databases->inbound_spd.table + 3 ;
	status = ipsec_spd_del(test_pointer, &databases->inbound_spd) ;
	if(status == IPSEC_STATUS_FAILURE)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("was not able to remove 2nd SPD entry")) ;
	}

	/* remove last entry */
	test_pointer = databases->inbound_spd.table + 9 ;
	status = ipsec_spd_del(test_pointer, &databases->inbound_spd) ;
	if(status == IPSEC_STATUS_FAILURE)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("was not able to remove 2nd SPD entry")) ;
	}

	/* remove 1st entry */
	test_pointer = databases->inbound_spd.table + 0 ;
	status = ipsec_spd_del(test_pointer, &databases->inbound_spd) ;
	if(status == IPSEC_STATUS_FAILURE)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_del", "FAILURE", ("was not able to remove 2nd SPD entry")) ;
	}
	
	if(databases)
		ipsec_spd_release_dbs(databases) ;

	return local_error_count ;
}


/**
 * Check if the Security Policy Database (SPD) lookup function works.
 * 6 tests are performed here.
 */
int test_spd_lookup(void)
{
	int 			local_error_count = 0 ;
	spd_entry 		*tmp_entry ;
	db_set_netif	*databases ;

	/* init the config data */
	memset(inbound_spd, 0, sizeof(inbound_spd)) ;
	memset(outbound_spd, 0, sizeof(outbound_spd)) ;
	memset(inbound_sad, 0, sizeof(inbound_sad)) ;
	memset(outbound_sad, 0, sizeof(outbound_sad)) ;

	memcpy(inbound_spd, inbound_spd_test, sizeof(inbound_spd_test)) ;
	memcpy(outbound_spd, outbound_spd_test, sizeof(outbound_spd_test)) ;
	memcpy(inbound_sad, inbound_sad_test, sizeof(inbound_sad_test)) ;
	memcpy(outbound_sad, outbound_sad_test, sizeof(outbound_sad_test)) ;

	/* init the table */
	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad) ;	
	if(databases == NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_lookup", "FAILURE", ("spd_inbound: unable to initialize the databases")) ;
	}

	tmp_entry = ipsec_spd_lookup((ipsec_ip_header*)ip_ftp_1, &databases->inbound_spd) ;
	if(tmp_entry != &databases->inbound_spd.table[0])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_lookup", "FALIURE", ("SPD lookup for 1st FTP packet failed")) ;
	}
	tmp_entry = ipsec_spd_lookup((ipsec_ip_header*)ip_ftp_2, &databases->inbound_spd) ;
	if(tmp_entry != &databases->inbound_spd.table[1])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_lookup", "FALIURE", ("SPD lookup for 2nd FTP packet failed")) ;
	}
	tmp_entry = ipsec_spd_lookup((ipsec_ip_header*)ip_rip, &databases->inbound_spd) ;
	if(tmp_entry != &databases->inbound_spd.table[2])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_lookup", "FALIURE", ("SPD lookup for RIP packet failed")) ;
	}
	tmp_entry = ipsec_spd_lookup((ipsec_ip_header*)ip_ah, &databases->inbound_spd) ;
	if(tmp_entry != &databases->inbound_spd.table[3])
	{
		local_error_count++ ;
		ipsec_print_ip((ipsec_ip_header*)ip_ah) ;
		IPSEC_LOG_TST("test_spd_lookup", "FALIURE", ("SPD lookup for AH packet failed")) ;
	}
	tmp_entry = ipsec_spd_lookup((ipsec_ip_header*)ip_esp, &databases->inbound_spd) ;
	if(tmp_entry != &databases->inbound_spd.table[4])
	{
		local_error_count++ ;
		ipsec_print_ip((ipsec_ip_header*)ip_esp) ;
		IPSEC_LOG_TST("test_spd_lookup", "FALIURE", ("SPD lookup for ESP packet failed")) ;
	}
	tmp_entry = ipsec_spd_lookup((ipsec_ip_header*)ip_def, &databases->inbound_spd) ;
	if(tmp_entry != &databases->inbound_spd.table[5])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_spd_lookup", "FALIURE", ("SPD lookup for default packet failed")) ;
	}

	if(databases)
		ipsec_spd_release_dbs(databases) ;

	return local_error_count ;
}

/**
 * Check if the Security Association Database (SAD) lookup function works.
 * 4 tests are performed here
 */
int test_sad_lookup(void)
{
	int local_error_count = 0 ;

	db_set_netif *databases ;

	/* init the config data */
	memset(inbound_spd, 0, sizeof(inbound_spd)) ;
	memset(outbound_spd, 0, sizeof(outbound_spd)) ;
	memset(inbound_sad, 0, sizeof(inbound_sad)) ;
	memset(outbound_sad, 0, sizeof(outbound_sad)) ;

	memcpy(inbound_spd, inbound_spd_test, sizeof(inbound_spd_test)) ;
	memcpy(outbound_spd, outbound_spd_test, sizeof(outbound_spd_test)) ;
	memcpy(inbound_sad, inbound_sad_test, sizeof(inbound_sad_test)) ;
	memcpy(outbound_sad, outbound_sad_test, sizeof(outbound_sad_test)) ;

	/* init the table */
	databases = ipsec_spd_load_dbs(inbound_spd, outbound_spd, inbound_sad, outbound_sad) ;
	if(databases == NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_lookup", "FAILURE", ("spd_inbound: unable to initialize the databases")) ;
	}

	if (ipsec_sad_lookup(ipsec_inet_addr("192.168.1.1"), IPSEC_PROTO_ESP, IPSEC_HTONL(0x1001), &databases->inbound_sad) != &databases->inbound_sad.table[0])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_lookup", "FAILURE", ("1st SA lookup falied")) ;
	}
	
	if (ipsec_sad_lookup(ipsec_inet_addr("192.168.1.2"), IPSEC_PROTO_AH, IPSEC_HTONL(0x1002), &databases->inbound_sad) != &databases->inbound_sad.table[1])
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_lookup", "FAILURE", ("2nd SA lookup falied")) ;
	}

	if (ipsec_sad_lookup(ipsec_inet_addr("192.168.1.1"), IPSEC_PROTO_ESP, IPSEC_HTONL(0x1002), &databases->inbound_sad) != NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_lookup", "FAILURE", ("3rd SA lookup found an SA but there was no one!")) ;
	}
	
	if (ipsec_sad_lookup(ipsec_inet_addr("192.168.1.1"), IPSEC_PROTO_AH, IPSEC_HTONL(0x1001), &databases->inbound_sad) != NULL)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_lookup", "FAILURE", ("4th SA lookup found an SA but there was no one!")) ;
	}

	if(databases)
		ipsec_spd_release_dbs(databases) ;

	return local_error_count ;
}

/**
 * Check if SPI lookup in the SAD works.
 * 2 tests are performed here.
 */
int test_sad_get_spi(void)
{
	int 	local_error_count = 0 ;
	__u32	spi ;

	spi = ipsec_sad_get_spi((ipsec_ip_header*)esp_hdr)	;
	if(spi != ipsec_htonl(0x1006))
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_get_spi", "FAILURE", ("unable to get SPI from ESP packet")) ;
	}
	
	spi = ipsec_sad_get_spi((ipsec_ip_header*)ah_hdr)	;
	if(spi != ipsec_htonl(0x1009))
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_sad_get_spi", "FAILURE", ("unable to get SPI from ESP packet")) ;
	}
		
	return local_error_count ;
}


int test_spd_flush(void)
{
	int local_error_count = 0;
	spd_entry storage[IPSEC_MAX_SPD_ENTRIES] = { EMPTY_SPD_ENTRY };
	spd_table table = { storage, NULL, NULL, IPSEC_MAX_SPD_ENTRIES };
	spd_entry ipv4_default = EMPTY_SPD_ENTRY;
	spd_entry ipv6_default = EMPTY_SPD_ENTRY;
	__u8 ipv6_src[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
	__u8 ipv6_dst[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };
	__u8 ipv6_mask[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* Seed the table with multiple entries so flush has real state to replace. */
	ipsec_spd_add(ipsec_inet_addr("192.168.1.10"), ipsec_inet_addr("255.255.255.255"),
			  ipsec_inet_addr("192.168.1.20"), ipsec_inet_addr("255.255.255.255"),
			  IPSEC_PROTO_TCP, ipsec_htons(1234), ipsec_htons(4321), POLICY_APPLY, &table);
	ipsec_spd_add(ipsec_inet_addr("10.0.0.0"), ipsec_inet_addr("255.0.0.0"),
			  ipsec_inet_addr("0.0.0.0"), ipsec_inet_addr("0.0.0.0"),
			  IPSEC_PROTO_UDP, 0, 0, POLICY_BYPASS, &table);

	ipv4_default.src = ipsec_inet_addr("0.0.0.0");
	ipv4_default.src_netaddr = ipsec_inet_addr("0.0.0.0");
	ipv4_default.dest = ipsec_inet_addr("0.0.0.0");
	ipv4_default.dest_netaddr = ipsec_inet_addr("0.0.0.0");
	ipv4_default.protocol = 0;
	ipv4_default.src_port = 0;
	ipv4_default.dest_port = 0;
	ipv4_default.policy = POLICY_BYPASS;

	if(ipsec_spd_flush(&table, &ipv4_default) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_flush", "FAILURE", ("unable to flush IPv4 SPD table"));
	}

	if((table.first != &table.table[0]) || (table.last != &table.table[0]))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_flush", "FAILURE", ("IPv4 flush did not rebuild a single-entry default list"));
	}

	if((table.table[0].policy != POLICY_BYPASS) || (table.table[0].use_flag != IPSEC_USED))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_flush", "FAILURE", ("IPv4 flush did not install the default entry correctly"));
	}

	ipsec_spd_set_ipv6(&ipv6_default, ipv6_src, ipv6_mask, ipv6_dst, ipv6_mask);
	ipv6_default.protocol = IPSEC_PROTO_TCP;
	ipv6_default.src_port = ipsec_htons(1000);
	ipv6_default.dest_port = ipsec_htons(2000);
	ipv6_default.policy = POLICY_APPLY;

	if(ipsec_spd_flush(&table, &ipv6_default) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_flush", "FAILURE", ("unable to flush IPv6 SPD table"));
	}

	if((table.first != &table.table[0]) || (table.last != &table.table[0]) || (table.table[0].addr_family != IPSEC_AF_INET6))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_flush", "FAILURE", ("IPv6 flush did not rebuild a single IPv6 default entry"));
	}

	if((memcmp(table.table[0].src_ipv6, ipv6_src, sizeof(ipv6_src)) != 0) ||
	   (memcmp(table.table[0].dest_ipv6, ipv6_dst, sizeof(ipv6_dst)) != 0) ||
	   (table.table[0].policy != POLICY_APPLY))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_flush", "FAILURE", ("IPv6 flush did not preserve the default entry fields"));
	}

	return local_error_count;
}


int test_spd_add_default_bypass(void)
{
	int local_error_count = 0;
	spd_entry storage[IPSEC_MAX_SPD_ENTRIES] = { EMPTY_SPD_ENTRY };
	spd_table table = { storage, NULL, NULL, IPSEC_MAX_SPD_ENTRIES };
	spd_entry *ipv4_default;
	spd_entry *ipv4_default_again;
	spd_entry *ipv6_default;
	spd_entry *ipv6_default_again;

	ipv4_default = ipsec_spd_add_default_bypass(IPSEC_AF_INET, &table);
	if((ipv4_default != &storage[0]) || (table.first != ipv4_default) || (table.last != ipv4_default))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_default_bypass", "FAILURE", ("IPv4 default bypass was not inserted as the only list entry"));
	}

	if((ipv4_default == NULL) || (ipv4_default->policy != POLICY_BYPASS) || (ipv4_default->addr_family != IPSEC_AF_INET))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_default_bypass", "FAILURE", ("IPv4 default bypass did not preserve fallback fields"));
	}

	ipv4_default_again = ipsec_spd_add_default_bypass(IPSEC_AF_INET, &table);
	if((ipv4_default_again != ipv4_default) || (ipv4_default->next != NULL) || (table.last != ipv4_default))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_default_bypass", "FAILURE", ("duplicate IPv4 default bypass was created"));
	}

	ipv6_default = ipsec_spd_add_default_bypass(IPSEC_AF_INET6, &table);
	if((ipv6_default != &storage[1]) || (table.last != ipv6_default) || (ipv4_default->next != ipv6_default) || (ipv6_default->prev != ipv4_default))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_default_bypass", "FAILURE", ("IPv6 default bypass was not appended after the existing IPv4 fallback"));
	}

	if((ipv6_default == NULL) || (ipv6_default->policy != POLICY_BYPASS) || (ipv6_default->addr_family != IPSEC_AF_INET6))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_default_bypass", "FAILURE", ("IPv6 default bypass did not preserve fallback fields"));
	}

	ipv6_default_again = ipsec_spd_add_default_bypass(IPSEC_AF_INET6, &table);
	if((ipv6_default_again != ipv6_default) || (table.last != ipv6_default) || (ipv6_default->next != NULL))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_default_bypass", "FAILURE", ("duplicate IPv6 default bypass was created"));
	}

	return local_error_count;
}


int test_spd_add_before_default_bypass(void)
{
	int local_error_count = 0;
	spd_entry storage[IPSEC_MAX_SPD_ENTRIES] = { EMPTY_SPD_ENTRY };
	spd_table table = { storage, NULL, NULL, IPSEC_MAX_SPD_ENTRIES };
	spd_entry *ipv4_rule;
	spd_entry *ipv4_rule_2;
	spd_entry *ipv6_rule;
	spd_entry *ipv4_fallback;
	__u8 ipv6_src[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31 };
	__u8 ipv6_dst[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32 };
	__u8 ipv6_mask[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	spd_entry *ipv6_fallback;

	if(ipsec_spd_add_default_bypass(IPSEC_AF_INET, &table) == NULL)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_before_default_bypass", "FAILURE", ("unable to seed the IPv4 default fallback"));
		return local_error_count;
	}

	ipv4_rule = ipsec_spd_add_ipv4_before_default_bypass(ipsec_inet_addr("192.168.10.10"),
										 ipsec_inet_addr("255.255.255.255"),
										 ipsec_inet_addr("192.168.10.20"),
										 ipsec_inet_addr("255.255.255.255"),
										 IPSEC_PROTO_TCP,
										 ipsec_htons(4000),
										 ipsec_htons(5000),
										 POLICY_APPLY,
										 &table);
	ipv4_fallback = find_default_bypass_for_family(&table, IPSEC_AF_INET);
	if((ipv4_rule == NULL) || (ipv4_fallback == NULL) || (table.first != ipv4_rule) || (table.last != ipv4_fallback))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_before_default_bypass", "FAILURE", ("IPv4 protected rule was not inserted before the IPv4 fallback"));
	}

	if((ipv4_rule == NULL) || (ipv4_rule->policy != POLICY_APPLY) || (ipv4_rule->next != ipv4_fallback) || (ipv4_fallback->prev != ipv4_rule))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_before_default_bypass", "FAILURE", ("IPv4 rule insertion did not preserve list order or selector fields"));
	}

	ipv4_rule_2 = ipsec_spd_add_ipv4_before_default_bypass(ipsec_inet_addr("10.1.0.0"),
										  ipsec_inet_addr("255.255.0.0"),
										  ipsec_inet_addr("10.2.0.0"),
										  ipsec_inet_addr("255.255.0.0"),
										  IPSEC_PROTO_UDP,
										  0,
										  0,
										  POLICY_BYPASS,
										  &table);
	ipv4_fallback = find_default_bypass_for_family(&table, IPSEC_AF_INET);
	if((ipv4_rule_2 == NULL) || (ipv4_fallback == NULL) || (table.first != ipv4_rule) || (table.last != ipv4_fallback) ||
	   (ipv4_rule->next != ipv4_rule_2) || (ipv4_rule_2->next != ipv4_fallback) || (ipv4_fallback->prev != ipv4_rule_2))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_before_default_bypass", "FAILURE", ("second IPv4 rule was not inserted ahead of the preserved fallback"));
	}

	ipv6_fallback = ipsec_spd_add_default_bypass(IPSEC_AF_INET6, &table);
	ipv6_rule = ipsec_spd_add_ipv6_before_default_bypass(ipv6_src,
								 ipv6_mask,
								 ipv6_dst,
								 ipv6_mask,
								 IPSEC_PROTO_UDP,
								 ipsec_htons(6000),
								 ipsec_htons(7000),
								 POLICY_APPLY,
								 &table);
	ipv6_fallback = find_default_bypass_for_family(&table, IPSEC_AF_INET6);
	if((ipv6_fallback == NULL) || (ipv6_rule == NULL) || (ipv6_rule->addr_family != IPSEC_AF_INET6) ||
	   (ipv6_rule->next != ipv6_fallback) || (ipv6_fallback->prev != ipv6_rule) || (table.last != ipv6_fallback))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_before_default_bypass", "FAILURE", ("IPv6 protected rule was not inserted before the IPv6 fallback"));
	}

	if((memcmp(ipv6_rule->src_ipv6, ipv6_src, sizeof(ipv6_src)) != 0) ||
	   (memcmp(ipv6_rule->dest_ipv6, ipv6_dst, sizeof(ipv6_dst)) != 0) ||
	   (ipv6_fallback->policy != POLICY_BYPASS))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_spd_add_before_default_bypass", "FAILURE", ("IPv6 rule insertion did not preserve IPv6 selectors or fallback policy"));
	}

	return local_error_count;
}


int test_sad_flush(void)
{
	int local_error_count = 0;
	sad_entry storage[IPSEC_MAX_SAD_ENTRIES] = { EMPTY_SAD_ENTRY };
	sad_table table = { storage, NULL, NULL };
	sad_entry template = { EMPTY_SAD_ENTRY };
	sad_entry *added;
	int index;

	template.dest = ipsec_inet_addr("192.168.1.20");
	template.dest_netaddr = ipsec_inet_addr("255.255.255.255");
	template.spi = ipsec_htonl(0x1001);
	template.protocol = IPSEC_PROTO_AH;
	template.mode = IPSEC_TRANSPORT;
	template.replay_win = IPSEC_SEQ_MAX_WINDOW;
	template.use_flag = IPSEC_USED;

	added = ipsec_sad_add(&template, &table);
	template.spi = ipsec_htonl(0x1002);
	ipsec_sad_add(&template, &table);
	if((added == NULL) || (table.first == NULL) || (table.last == NULL))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_flush", "FAILURE", ("unable to seed SAD table before flush"));
	}

	if(ipsec_sad_flush(&table) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_flush", "FAILURE", ("unable to flush SAD table"));
	}

	if((table.first != NULL) || (table.last != NULL))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_flush", "FAILURE", ("SAD flush did not clear list pointers"));
	}

	for(index = 0; index < IPSEC_MAX_SAD_ENTRIES; index++)
	{
		if(storage[index].use_flag != IPSEC_FREE)
		{
			local_error_count++;
			IPSEC_LOG_TST("test_sad_flush", "FAILURE", ("SAD flush did not clear table entries"));
			break;
		}
	}

	added = ipsec_sad_add(&template, &table);
	if((added != &storage[0]) || (table.first != &storage[0]) || (table.last != &storage[0]))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_flush", "FAILURE", ("SAD table was not reusable after flush"));
	}

	return local_error_count;
}


int test_sad_add(void)
{
	int local_error_count = 0;
	sad_entry storage[IPSEC_MAX_SAD_ENTRIES] = { EMPTY_SAD_ENTRY };
	sad_table table = { storage, NULL, NULL };
	sad_entry ipv4_template = { EMPTY_SAD_ENTRY };
	sad_entry ipv6_template = { EMPTY_SAD_ENTRY };
	sad_entry *first;
	sad_entry *second;
	__u8 ipv6_dest[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20 };
	__u8 ipv6_mask[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	ipv4_template.dest = ipsec_inet_addr("192.168.1.20");
	ipv4_template.dest_netaddr = ipsec_inet_addr("255.255.255.255");
	ipv4_template.spi = ipsec_htonl(0x1001);
	ipv4_template.protocol = IPSEC_PROTO_AH;
	ipv4_template.mode = IPSEC_TRANSPORT;
	ipv4_template.sequence_number = 3;
	ipv4_template.replay_win = IPSEC_SEQ_MAX_WINDOW;
	ipv4_template.replay_last_seq = 2;
	ipv4_template.replay_bitmap = 0x03;
	ipv4_template.path_mtu = 1400;
	ipv4_template.auth_alg = IPSEC_HMAC_SHA1;
	memcpy(ipv4_template.authkey, "01234567890123456789", IPSEC_AUTH_SHA1_KEY_LEN);

	first = ipsec_sad_add(&ipv4_template, &table);
	if((first != &storage[0]) || (table.first != first) || (table.last != first))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_add", "FAILURE", ("first SAD entry was not inserted at the head of the table"));
	}

	if((first == NULL) || (first->sequence_number != 3) || (first->replay_last_seq != 2) || (first->replay_bitmap != 0x03))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_add", "FAILURE", ("first SAD entry did not preserve sequence or replay fields"));
	}

	ipv6_template = ipv4_template;
	ipv6_template.spi = ipsec_htonl(0x1002);
	ipsec_sad_set_ipv6(&ipv6_template, ipv6_dest, ipv6_mask);
	second = ipsec_sad_add(&ipv6_template, &table);
	if(second != &storage[1])
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_add", "FAILURE", ("second SAD entry did not use the next free table slot"));
	}

	if(table.last != second)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_add", "FAILURE", ("second SAD entry did not update the table tail"));
	}

	if((second == NULL) || (second->prev != first) || (first->next != second))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_add", "FAILURE", ("second SAD entry was not linked after the first entry"));
	}

	if((second == NULL) || (second->addr_family != IPSEC_AF_INET6) || (memcmp(second->dest_ipv6, ipv6_dest, sizeof(ipv6_dest)) != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_add", "FAILURE", ("IPv6 SAD fields were not preserved during insertion"));
	}

	return local_error_count;
}


int test_sad_del(void)
{
	int local_error_count = 0;
	sad_entry storage[IPSEC_MAX_SAD_ENTRIES] = { EMPTY_SAD_ENTRY };
	sad_table table = { storage, NULL, NULL };
	sad_entry template = { EMPTY_SAD_ENTRY };
	sad_entry *first;
	sad_entry *second;
	sad_entry *third;

	template.dest = ipsec_inet_addr("192.168.1.20");
	template.dest_netaddr = ipsec_inet_addr("255.255.255.255");
	template.protocol = IPSEC_PROTO_AH;
	template.mode = IPSEC_TRANSPORT;
	template.replay_win = IPSEC_SEQ_MAX_WINDOW;

	template.spi = ipsec_htonl(0x1001);
	first = ipsec_sad_add(&template, &table);
	template.spi = ipsec_htonl(0x1002);
	second = ipsec_sad_add(&template, &table);
	template.spi = ipsec_htonl(0x1003);
	third = ipsec_sad_add(&template, &table);

	if((first == NULL) || (second == NULL) || (third == NULL))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("unable to seed SAD table before deletion tests"));
		return local_error_count;
	}

	if(ipsec_sad_del(second, &table) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("unable to delete middle SAD entry"));
	}

	if((first->next != third) || (third->prev != first) || (second->use_flag != IPSEC_FREE))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("deleting the middle SAD entry did not relink the list"));
	}

	if(ipsec_sad_del(first, &table) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("unable to delete first SAD entry"));
	}

	if((table.first != third) || (third->prev != NULL))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("deleting the first SAD entry did not advance the head"));
	}

	if(ipsec_sad_del(third, &table) != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("unable to delete last SAD entry"));
	}

	if((table.first != NULL) || (table.last != NULL))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("deleting the final SAD entry did not clear the table"));
	}

	if((ipsec_sad_del(second, &table) != IPSEC_STATUS_FAILURE) ||
	   (ipsec_sad_del(storage - 1, &table) != IPSEC_STATUS_FAILURE))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_del", "FAILURE", ("invalid SAD deletions were not rejected"));
	}

	return local_error_count;
}

/*
 * Verifies that replay tracking is isolated per SA, survives table insertion, and
 * can be reset explicitly when an inbound SA is reprovisioned.
 */
int test_sad_replay_state(void)
{
	int local_error_count = 0;
	sad_entry first = { EMPTY_SAD_ENTRY };
	sad_entry second = { EMPTY_SAD_ENTRY };
	sad_entry copied_template = { EMPTY_SAD_ENTRY };
	sad_entry storage[IPSEC_MAX_SAD_ENTRIES] = { EMPTY_SAD_ENTRY };
	sad_table table = { storage, NULL, NULL };
	sad_entry *copied;

	first.replay_win = IPSEC_SEQ_MAX_WINDOW;
	second.replay_win = IPSEC_SEQ_MAX_WINDOW;
	copied_template.replay_win = IPSEC_SEQ_MAX_WINDOW;

	/* Advance replay state on only one SA and make sure the second one remains untouched. */
	if(ipsec_update_replay_window(1, &first.replay_last_seq, &first.replay_bitmap) != IPSEC_AUDIT_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_replay_state", "FAILURE", ("unable to update replay state on first SA"));
	}

	if(ipsec_check_replay_window(1, second.replay_last_seq, second.replay_bitmap) != IPSEC_AUDIT_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_replay_state", "FAILURE", ("second SA inherited replay state from first SA"));
	}

	/* Table insertion must copy the replay window fields verbatim into persistent SAD storage. */
	copied_template.replay_last_seq = 7;
	copied_template.replay_bitmap = 0x55;
	copied = ipsec_sad_add(&copied_template, &table);
	if((copied == NULL) || (copied->replay_last_seq != 7) || (copied->replay_bitmap != 0x55))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_replay_state", "FAILURE", ("ipsec_sad_add() did not preserve per-SA replay state"));
	}

	ipsec_sad_reset_replay(&first);
	if((first.replay_last_seq != 0) || (first.replay_bitmap != 0))
	{
		local_error_count++;
		IPSEC_LOG_TST("test_sad_replay_state", "FAILURE", ("ipsec_sad_reset_replay() did not clear replay state"));
	}

	return local_error_count;
}


/**
 * Main test function for the SA tests.
 * It does nothing but calling the subtests one after the other.
 */
void sa_test(test_result *global_results)
{
	test_result 	sub_results	= {
					 98, 			
					 15,			
						  0, 			
						  0, 		
					};

	int retcode;

	retcode = test_spd_init() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_init()", (" "));

	retcode = test_spd_init_dbs() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_init_dbs()", (" "));

	retcode = test_spd_get_free() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_free()", (" "));

	retcode = test_spd_add() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_add()", (" "));

	retcode = test_spd_del() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_del()", (" "));

	retcode = test_spd_lookup() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_lookup()", (" "));

	retcode = test_sad_add() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_sad_add()", (" "));

	retcode = test_sad_del() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_sad_del()", (" "));

	retcode = test_sad_lookup() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_sad_lookup()", (" "));

	retcode = test_sad_get_spi() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_sad_get_spi()", (" "));

	retcode = test_spd_flush() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_flush()", (" "));

	retcode = test_spd_add_default_bypass() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_add_default_bypass()", (" "));

	retcode = test_spd_add_before_default_bypass() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_spd_add_before_default_bypass()", (" "));

	retcode = test_sad_flush() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_sad_flush()", (" "));

	retcode = test_sad_replay_state() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "sa_test_sad_replay_state()", (" "));

	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}


