/*
 * AWS IoT Device SDK for Embedded C 202012.01
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

#ifndef _PROVISION_PSA_UTILS_H_
#define _PROVISION_PSA_UTILS_H_

/* Mbed includes */
#include "mbed.h"
/* To include psa/crypto.h > psa/crypto_extra.h > psa/mbedtls_ecc_group_to_psa.h,
 * Mbed TLS configuration must place in front. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"
#include "psa/protected_storage.h"
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Install private key/public key/certificate for non-opaque use */
void provpsa_install_nonconf(const unsigned char *pem, size_t pem_size, psa_storage_uid_t uid);

/* Install private key/public key for opaque use */
void provpsa_install_pvtpub(const unsigned char *pem, size_t pem_size, psa_key_id_t key_id, bool is_pvt);
void provpsa_install_pvtpub_intern(mbedtls_pk_context *pk_ctx, psa_key_id_t key_id, bool is_pvt);

/* Install private key/public key for non-opaque use when opaque use is not supported */
void provpsa_install_pvtpub_extra_nonconf(const unsigned char *pem,
                                                size_t pem_size,
                                                psa_key_id_t key_id,
                                                psa_storage_uid_t uid);

/* Install public key by certificate for opaque use */
void provpsa_install_pubkey_by_crt(const unsigned char *pem, size_t pem_size, psa_key_id_t pubkey_id);

/* Check key pair for private key/public key */
void provpsa_check_pair_pvtpub(psa_key_id_t pvtkey_id,
                                     psa_key_id_t pubkey_id);
                            
/* Check key pair for private key/certificate */
void provpsa_check_pair_pvtcrt(psa_key_id_t pvtkey_id,
                                     psa_storage_uid_t crt_uid,
                                     psa_storage_uid_t pvtkey_uid);

#ifdef __cplusplus
}
#endif

#endif /* _PROVISION_PSA_UTILS_H_ */
