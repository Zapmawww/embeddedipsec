/*
 * embedded IPsec
 * Copyright (c) 2026 Zapmawww
 * All rights reserved.
 */

#include <string.h>

#include "ipsec/aes_cbc.h"

#include "aes.h"

ipsec_status ipsec_aes_cbc_encrypt_buffer(__u8 *data, int len, const __u8 *key, const __u8 *iv)
{
	struct AES_ctx ctx;

	if((data == NULL) || (key == NULL) || (iv == NULL) || (len < 0) || ((len % IPSEC_AES_CBC_BLOCK_SIZE) != 0))
	{
		return IPSEC_STATUS_BAD_KEY;
	}

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, data, (size_t)len);
	memset(&ctx, 0, sizeof(ctx));
	return IPSEC_STATUS_SUCCESS;
}

ipsec_status ipsec_aes_cbc_decrypt_buffer(__u8 *data, int len, const __u8 *key, const __u8 *iv)
{
	struct AES_ctx ctx;

	if((data == NULL) || (key == NULL) || (iv == NULL) || (len < 0) || ((len % IPSEC_AES_CBC_BLOCK_SIZE) != 0))
	{
		return IPSEC_STATUS_BAD_KEY;
	}

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, data, (size_t)len);
	memset(&ctx, 0, sizeof(ctx));
	return IPSEC_STATUS_SUCCESS;
}