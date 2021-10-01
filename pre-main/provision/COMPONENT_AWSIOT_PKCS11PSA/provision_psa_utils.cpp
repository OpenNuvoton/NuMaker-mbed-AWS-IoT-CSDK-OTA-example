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

#include "provision_psa_utils.h"
#include "mbedtls/base64.h"

/* TODO: Make consistent with PKCS11 MAX_PRIVATE_KEY_SIZE/MAX_PUBLIC_KEY_SIZE */
//#define MAX_PRIVATE_KEY_SIZE    pkcs11OBJECT_MAX_SIZE
//#define MAX_PUBLIC_KEY_SIZE     310
#define PROVPSA_PVTKEY_MAXSIZE      2048
#define PROVPSA_PUBKEY_MAXSIZE      2048

#define PROVPSA_ASSERT_EQUAL(EXP, ACT)                      \
    do {                                                    \
        volatile int exp = (EXP);                           \
        volatile int act = (ACT);                           \
        if (exp != act) {                                   \
            printf("%s:%d:FAIL:", __FILE__, __LINE__);      \
            printf("Expected %d Was %d\r\n", exp, act);     \
            MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_ASSERTION_FAILED),  \
                       "Provision with PSA failed");        \
        }                                                   \
    } while(0)

#define PROVPSA_ASSERT_NOT_EQUAL(EXP, ACT)                  \
    do {                                                    \
        volatile int exp = (EXP);                           \
        volatile int act = (ACT);                           \
        if (exp == act) {                                   \
            printf("%s:%d:FAIL:", __FILE__, __LINE__);      \
            printf("Expected %d Not Equal %d\r\n", exp, act);   \
            MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_ASSERTION_FAILED),  \
                       "Provision with PSA failed");        \
        }                                                   \
    } while(0)

#define PROVPSA_ASSERT_TRUE(COND)                           \
    do {                                                    \
        if (!(COND)) {                                      \
            MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_ASSERTION_FAILED),  \
                       "Provision with PSA failed");        \
        }                                                   \
    } while (0)

/* 32 bytes for sha256 (32 = 256 / 8) */
static const uint8_t hash_sha256[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
};

extern "C"
int convert_pem_to_der( const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen );

void provpsa_install_nonconf(const unsigned char *pem, size_t pem_size, psa_storage_uid_t uid)
{
    /* Skip on installed */
    {
        struct psa_storage_info_t stor_info;
        if (PSA_SUCCESS == psa_ps_get_info(uid, &stor_info)) {
            printf("Has installed, SKIP\r\n");
            return;
        }
    }

    /* DER is about 3/4 PEM, so PEM space for DER is enough */
    unsigned char *crt_der = (unsigned char *) malloc(pem_size);
    size_t der_len = pem_size;
    PROVPSA_ASSERT_EQUAL(0, convert_pem_to_der(pem,
                                               pem_size,
                                               crt_der,
                                               &der_len));
    PROVPSA_ASSERT_NOT_EQUAL(0, der_len);
    PROVPSA_ASSERT_NOT_EQUAL(pem_size, der_len);
    printf("Certificate: PEM size: %d, DER size: %d\r\n",
           pem_size, der_len);

    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_set(uid,
                                                 der_len,
                                                 crt_der,
                                                 PSA_STORAGE_FLAG_NONE));

    free(crt_der);
}

void provpsa_install_pvtpub(const unsigned char *pem, size_t pem_size, psa_key_id_t key_id, bool is_pvt)
{
    mbedtls_pk_context pk_ctx;

    mbedtls_pk_init(&pk_ctx);

    if (is_pvt) {
        PROVPSA_ASSERT_EQUAL(0, mbedtls_pk_parse_key(&pk_ctx, pem, pem_size, NULL, 0));
    } else {
        PROVPSA_ASSERT_EQUAL(0, mbedtls_pk_parse_public_key(&pk_ctx, pem, pem_size));
    }

    provpsa_install_pvtpub_intern(&pk_ctx, key_id, is_pvt);

    /* Clean up */
    mbedtls_pk_free(&pk_ctx);
}

void provpsa_install_pvtpub_intern(mbedtls_pk_context *pk_ctx, psa_key_id_t key_id, bool is_pvt)
{
    /* Skip on installed */
    {
        psa_key_id_t key_handle = 0;
        if (PSA_SUCCESS == psa_open_key(key_id, &key_handle)) {
            printf("Has installed, SKIP\r\n");
            PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(key_handle));
            return;
        }
    }

    mbedtls_pk_type_t pk_type;

    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_type_t key_type;
    psa_algorithm_t key_algorithm;
    //psa_key_usage_t key_usage;
    unsigned char *key_data = NULL;
    size_t key_size = 0;
    psa_key_id_t key_handle = 0;
    unsigned char *key_raw_data = NULL;
    int key_raw_data_size;
    int key_raw_data_maxsize = is_pvt ? PROVPSA_PVTKEY_MAXSIZE : PROVPSA_PUBKEY_MAXSIZE;

    key_raw_data = (unsigned char *) malloc(key_raw_data_maxsize);

    pk_type = mbedtls_pk_get_type(pk_ctx);
    switch (pk_type) {
        case MBEDTLS_PK_RSA: {
            if (is_pvt) {
                key_raw_data_size = mbedtls_pk_write_key_der(pk_ctx, key_raw_data, key_raw_data_maxsize);
                key_type = PSA_KEY_TYPE_RSA_KEY_PAIR;
            } else {
                key_raw_data_size = mbedtls_pk_write_pubkey_der(pk_ctx, key_raw_data, key_raw_data_maxsize);
                key_type = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
            }
            PROVPSA_ASSERT_TRUE(key_raw_data_size > 0);
            key_data = key_raw_data + (key_raw_data_maxsize - key_raw_data_size);
            key_size = key_raw_data_size;

            mbedtls_rsa_context *rsa_ctx = mbedtls_pk_rsa(*pk_ctx);
            switch (rsa_ctx->padding) {
                case MBEDTLS_RSA_PKCS_V15:
                    key_algorithm = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
                    break;

                case MBEDTLS_RSA_PKCS_V21:
                    key_algorithm = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
                    break;

                default:
                    printf("Invalid RSA padding %d\r\n", rsa_ctx->padding);
                    PROVPSA_ASSERT_TRUE(0);
            }
            break;
        }
        case MBEDTLS_PK_ECKEY: {
            mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pk_ctx);
            size_t curve_bits = 0;
            psa_ecc_family_t psa_curve_id = mbedtls_ecc_group_to_psa(ec->grp.id, &curve_bits);
            PROVPSA_ASSERT_TRUE(psa_curve_id != 0);
            PROVPSA_ASSERT_TRUE(curve_bits != 0);
            key_algorithm = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
            if (is_pvt) {
                key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(psa_curve_id);
                key_raw_data_size = (ec->grp.nbits + 7) / 8;
                PROVPSA_ASSERT_EQUAL(0, mbedtls_mpi_write_binary(&ec->d,
                                                                 key_raw_data,
                                                                 key_raw_data_size));
                key_data = key_raw_data;
            } else {
                key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(psa_curve_id);
                key_data = key_raw_data + key_raw_data_maxsize;
                key_raw_data_size = mbedtls_pk_write_pubkey(&key_data, key_raw_data, pk_ctx);
                PROVPSA_ASSERT_TRUE(key_raw_data_size > 0);
            }
            key_size = key_raw_data_size;
            break;
        }
        default:
            printf("Unsupported key type: %d\r\n", pk_type);
            PROVPSA_ASSERT_TRUE(0);
    }

    psa_set_key_id(&key_attributes, key_id);
    psa_set_key_usage_flags(&key_attributes,
                            is_pvt ? PSA_KEY_USAGE_SIGN_HASH : PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_algorithm);
    psa_set_key_type(&key_attributes, key_type);
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_import_key(&key_attributes,
                                                     (const uint8_t *) key_data,
                                                     key_size,
                                                     &key_handle));
    PROVPSA_ASSERT_EQUAL(key_id, key_handle);

    /* Clean up */
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(key_handle));
    free(key_raw_data);
}

void provpsa_install_pvtpub_extra_nonconf(const unsigned char *pem,
                                          size_t pem_size,
                                          psa_key_id_t key_id,
                                          psa_storage_uid_t uid)
{
    /* Mbed TLS hasn't supported non-ECC key as opaque yet
     *
     * Detecting this, install to PSA storage for non-opaque use.
     * https://github.com/ARMmbed/mbed-os/blob/3377f083b3a6bd7a1b45ed2cea5cf083b9007527/connectivity/mbedtls/source/pk.c#L169-L171
     */
    psa_key_id_t key_handle = 0;
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_open_key(key_id, &key_handle));
    PROVPSA_ASSERT_EQUAL(key_id, key_handle);

    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    int rc = mbedtls_pk_setup_opaque(&pk_ctx, key_id);
    if (rc == MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE) {
        printf("Mbed TLS hasn't supported non-ECC key as opaque yet. "
               "Install to PSA storage additionally for non-opaque use.\r\n");
        provpsa_install_nonconf(pem, pem_size, uid);
    } else {
        PROVPSA_ASSERT_EQUAL(0, rc);
    }

    /* Clean up */
    mbedtls_pk_free(&pk_ctx);
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(key_handle));
}

void provpsa_install_pubkey_by_crt(const unsigned char *pem,
                                   size_t pem_size,
                                   psa_key_id_t pubkey_id)
{
    mbedtls_x509_crt crt_chain;
    mbedtls_x509_crt_init(&crt_chain);
    PROVPSA_ASSERT_EQUAL(0, mbedtls_x509_crt_parse(&crt_chain, pem, pem_size));

    provpsa_install_pvtpub_intern(&crt_chain.pk, pubkey_id, false);

    /* Clean up */
    mbedtls_x509_crt_free(&crt_chain);
}

void provpsa_check_pair_pvtpub(psa_key_id_t pvtkey_id,
                               psa_key_id_t pubkey_id)
{
    psa_key_id_t pvtkey_handle = 0;
    psa_key_id_t pubkey_handle = 0;

    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_open_key(pvtkey_id, &pvtkey_handle));
    PROVPSA_ASSERT_EQUAL(pvtkey_id, pvtkey_handle);
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_open_key(pubkey_id, &pubkey_handle));
    PROVPSA_ASSERT_EQUAL(pubkey_id, pubkey_handle);

    psa_key_attributes_t pubkey_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t pvtkey_attributes = PSA_KEY_ATTRIBUTES_INIT;

    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_get_key_attributes(pvtkey_id,
                                                             &pvtkey_attributes));
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_get_key_attributes(pubkey_id,
                                                             &pubkey_attributes));

    psa_algorithm_t pvtkey_alg = psa_get_key_algorithm(&pvtkey_attributes);
    psa_algorithm_t pubkey_alg = psa_get_key_algorithm(&pubkey_attributes);
    PROVPSA_ASSERT_EQUAL(pvtkey_alg, pubkey_alg);

    if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(pvtkey_alg)) {
        pvtkey_alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    } else if (PSA_ALG_IS_RSA_PSS(pvtkey_alg)) {
        pvtkey_alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
    } else if (PSA_ALG_IS_ECDSA(pvtkey_alg)) {
        pvtkey_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    } else {
        printf("Unsupported PSA algorithm: 0x%08x\r\n", pvtkey_alg);
        PROVPSA_ASSERT_TRUE(0);
    }
    pubkey_alg = pvtkey_alg;

    size_t sig_size_req = PSA_SIGN_OUTPUT_SIZE(psa_get_key_type(&pvtkey_attributes), 
                                               psa_get_key_bits(&pvtkey_attributes),
                                               pvtkey_alg);
    printf("Signature size (required): %d\r\n", sig_size_req);

    uint8_t *sig = (uint8_t *) malloc(sig_size_req);
    size_t sig_size_act = 0;

    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_sign_hash(pvtkey_id,
                                                    pvtkey_alg,
                                                    hash_sha256,
                                                    sizeof(hash_sha256),
                                                    sig,
                                                    sig_size_req,
                                                    &sig_size_act));
    printf("Signature size (actual): %d\r\n", sig_size_act);
    PROVPSA_ASSERT_TRUE(sig_size_act == sig_size_req);

    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_verify_hash(pubkey_id,
                                                      pubkey_alg,
                                                      hash_sha256,
                                                      sizeof(hash_sha256),
                                                      sig,
                                                      sig_size_act));

    /* Clean up */
    free(sig);
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(pvtkey_handle));
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(pubkey_handle));
}

void provpsa_check_pair_pvtcrt(psa_key_id_t pvtkey_id,
                               psa_storage_uid_t crt_uid,
                               psa_storage_uid_t pvtkey_uid)
{
    /* Don't mix psa_sign_hash/psa_sign_verify with mbedtls_pk_sign/mbedtls_pk_verify
     *
     * For example, for ECC, psa_sign_hash() signature is PSA format, but
     * mbedtls_pk_verify() expects ASN.1 sequence.
     */

    psa_key_id_t pvtkey_handle = 0;
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_open_key(pvtkey_id, &pvtkey_handle));
    PROVPSA_ASSERT_EQUAL(pvtkey_id, pvtkey_handle);
    
    mbedtls_pk_context pvtkey_ctx;
    mbedtls_pk_init(&pvtkey_ctx);
    if (MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE ==
        mbedtls_pk_setup_opaque(&pvtkey_ctx, pvtkey_id)) {
        mbedtls_pk_free(&pvtkey_ctx);
        mbedtls_pk_init(&pvtkey_ctx);

        struct psa_storage_info_t pvtkey_stor_info;
        PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get_info(pvtkey_uid,
                                                          &pvtkey_stor_info));

        uint8_t *pvtkey = (uint8_t *) malloc(pvtkey_stor_info.size);
        size_t pvtkey_size = 0;
        PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get(pvtkey_uid,
                                                     0,
                                                     pvtkey_stor_info.size,
                                                     pvtkey,
                                                     &pvtkey_size));
        PROVPSA_ASSERT_TRUE(pvtkey_size == pvtkey_stor_info.size);
        PROVPSA_ASSERT_TRUE(pvtkey_size != 0);

        PROVPSA_ASSERT_EQUAL(0, mbedtls_pk_parse_key(&pvtkey_ctx,
                                                     (const unsigned char *) pvtkey,
                                                     pvtkey_size,
                                                     NULL,
                                                     0));

        free(pvtkey);
    }

    struct psa_storage_info_t crt_stor_info;
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get_info(crt_uid,
                                                      &crt_stor_info));

    uint8_t *crt = (uint8_t *) malloc(crt_stor_info.size);
    size_t crt_size = 0;
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_ps_get(crt_uid,
                                                 0,
                                                 crt_stor_info.size,
                                                 crt,
                                                 &crt_size));
    PROVPSA_ASSERT_TRUE(crt_size == crt_stor_info.size);
    PROVPSA_ASSERT_TRUE(crt_size != 0);

    mbedtls_x509_crt crt_chain;
    mbedtls_x509_crt_init(&crt_chain);
    PROVPSA_ASSERT_EQUAL(0, mbedtls_x509_crt_parse(&crt_chain, crt, crt_size));

    /* Not support for the opaque path. Do it manually. */
    //PROVPSA_ASSERT_EQUAL(0, mbedtls_pk_check_pair(&crt_chain.pk, &pvtkey_ctx));

    uint8_t *sig = (uint8_t *) malloc(MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    size_t sig_size_act = 0;

    printf("MBEDTLS_PK_SIGNATURE_MAX_SIZE: %d\r\n", MBEDTLS_PK_SIGNATURE_MAX_SIZE);

    PROVPSA_ASSERT_EQUAL(0, mbedtls_pk_sign(&pvtkey_ctx,
                                            MBEDTLS_MD_SHA256,
                                            hash_sha256,
                                            sizeof(hash_sha256),
                                            sig,
                                            &sig_size_act,
                                            NULL,
                                            NULL));

    printf("sig_size_act: %d\r\n", sig_size_act);

    PROVPSA_ASSERT_EQUAL(0, mbedtls_pk_verify(&crt_chain.pk,
                                              MBEDTLS_MD_SHA256,
                                              hash_sha256,
                                              sizeof(hash_sha256),
                                              sig,
                                              sig_size_act));

    /* Clean up */
    free(sig);
    mbedtls_x509_crt_free(&crt_chain);
    free(crt);
    mbedtls_pk_free(&pvtkey_ctx);
    PROVPSA_ASSERT_EQUAL(PSA_SUCCESS, psa_close_key(pvtkey_handle));
}
