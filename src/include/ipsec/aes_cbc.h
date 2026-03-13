/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 */

#ifndef __IPSEC_AES_CBC_H__
#define __IPSEC_AES_CBC_H__

#include "ipsec/ipsec.h"

ipsec_status ipsec_aes_cbc_encrypt_buffer(__u8 *data, int len, const __u8 *key, const __u8 *iv);
ipsec_status ipsec_aes_cbc_decrypt_buffer(__u8 *data, int len, const __u8 *key, const __u8 *iv);

#endif