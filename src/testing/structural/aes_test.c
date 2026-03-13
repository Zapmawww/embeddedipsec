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

/** @file aes_test.c
 *  @brief Test functions for AES-CBC wrapper code
 */

#include <string.h>

#include "ipsec/aes_cbc.h"
#include "ipsec/debug.h"
#include "testing/structural/structural_test.h"

static const unsigned char aes_test_key[IPSEC_AES_CBC_KEY_LEN] =
{
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char aes_test_iv[IPSEC_AES_CBC_BLOCK_SIZE] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char aes_test_plaintext[4 * IPSEC_AES_CBC_BLOCK_SIZE] =
{
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const unsigned char aes_test_ciphertext[4 * IPSEC_AES_CBC_BLOCK_SIZE] =
{
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
	0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
	0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
	0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
	0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
	0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

static int aes_test_encrypt_vector(void)
{
	int local_error_count;
	unsigned char ciphertext[sizeof(aes_test_plaintext)];
	ipsec_status ret_val;

	local_error_count = 0;
	memcpy(ciphertext, aes_test_plaintext, sizeof(ciphertext));
	ret_val = ipsec_aes_cbc_encrypt_buffer(ciphertext, (int)sizeof(ciphertext), aes_test_key, aes_test_iv);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("aes_test_encrypt_vector", "FAILURE", ("AES-CBC encrypt wrapper returned %d", ret_val));
		return local_error_count;
	}

	if(memcmp(ciphertext, aes_test_ciphertext, sizeof(ciphertext)) != 0)
	{
		local_error_count++;
		IPSEC_LOG_TST("aes_test_encrypt_vector", "FAILURE", ("AES-CBC encrypt wrapper did not match the NIST CBC vector"));
	}

	return local_error_count;
}

static int aes_test_decrypt_vector(void)
{
	int local_error_count;
	unsigned char plaintext[sizeof(aes_test_ciphertext)];
	ipsec_status ret_val;

	local_error_count = 0;
	memcpy(plaintext, aes_test_ciphertext, sizeof(plaintext));
	ret_val = ipsec_aes_cbc_decrypt_buffer(plaintext, (int)sizeof(plaintext), aes_test_key, aes_test_iv);
	if(ret_val != IPSEC_STATUS_SUCCESS)
	{
		local_error_count++;
		IPSEC_LOG_TST("aes_test_decrypt_vector", "FAILURE", ("AES-CBC decrypt wrapper returned %d", ret_val));
		return local_error_count;
	}

	if(memcmp(plaintext, aes_test_plaintext, sizeof(plaintext)) != 0)
	{
		local_error_count++;
		IPSEC_LOG_TST("aes_test_decrypt_vector", "FAILURE", ("AES-CBC decrypt wrapper did not recover the NIST CBC plaintext"));
	}

	return local_error_count;
}

static int aes_test_rejects_bad_length(void)
{
	unsigned char buffer[IPSEC_AES_CBC_BLOCK_SIZE + 1];
	ipsec_status ret_val;

	memcpy(buffer, aes_test_plaintext, sizeof(buffer));
	ret_val = ipsec_aes_cbc_encrypt_buffer(buffer, (int)sizeof(buffer), aes_test_key, aes_test_iv);
	if(ret_val != IPSEC_STATUS_BAD_KEY)
	{
		IPSEC_LOG_TST("aes_test_rejects_bad_length", "FAILURE", ("AES-CBC encrypt wrapper accepted a non-block-aligned length"));
		return 1;
	}

	return 0;
}

void aes_test(test_result *global_results)
{
	test_result sub_results = {
		3,
		3,
		0,
		0,
	};
	int retcode;

	retcode = aes_test_encrypt_vector();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "aes_test_encrypt_vector()", ("NIST SP 800-38A AES-128-CBC"));

	retcode = aes_test_decrypt_vector();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "aes_test_decrypt_vector()", ("NIST SP 800-38A AES-128-CBC"));

	retcode = aes_test_rejects_bad_length();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "aes_test_rejects_bad_length()", ("wrapper contract check"));

	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}