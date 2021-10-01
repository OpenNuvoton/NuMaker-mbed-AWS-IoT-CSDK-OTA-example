/*
 * Copyright (c) 2020, Nuvoton Technology Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Mbed include */
#include "mbed.h"
#include "KVStore.h"
#include "kvstore_global_api.h"

/* AWS credential include */
/* Never include. Get credentials from provision. */
//#include "aws_credentials.h"
#include "aws_credentials_provision_kvstore.h"
#include "core_pkcs11_config.h"

/* Stringize */
#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

/* Convert to KVStore default fully-qualified key path */
#define KV_DEF_FQ_KEY(KEY)                      \
    "/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/" KEY

/* Fetch provisioned credential */
#define PROV_CRED(KEY, P_CRED, P_CRED_SIZE)                         \
    static const uint8_t *cred_value_ = nullptr;                    \
    static size_t cred_value_size_ = 0;                             \
    bool cred_avail = true;                                         \
                                                                    \
    if (cred_value_ == nullptr) {                                   \
        cred_avail = credential_from_kvstore(KV_DEF_FQ_KEY(KEY),    \
                                             &cred_value_,          \
                                             &cred_value_size_);    \
    }                                                               \
                                                                    \
    if (cred_avail) {                                               \
        if (P_CRED) {                                               \
            *P_CRED = cred_value_;                                  \
        }                                                           \
        if (P_CRED_SIZE) {                                          \
            *P_CRED_SIZE = cred_value_size_;                        \
        }                                                           \
    }

namespace aws {
namespace credentials {
namespace provision {
    /* Load credential from KVStore */
    bool credential_from_kvstore(const char *cred_key, const uint8_t **p_cred, size_t *p_cred_size);
}}}

bool aws::credentials::provision::rootCACrt(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(pkcs11configLABEL_ROOT_CERTIFICATE, p_cred, p_cred_size)
    return cred_avail;
}

bool aws::credentials::provision::deviceCrt(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, p_cred, p_cred_size)
    return cred_avail;
}

bool aws::credentials::provision::devicePubKey(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, p_cred, p_cred_size)
    return cred_avail;
}

bool aws::credentials::provision::devicePvtKey(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, p_cred, p_cred_size)
    return cred_avail;
}

bool aws::credentials::provision::codeVerKey(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(pkcs11configLABEL_CODE_VERIFICATION_KEY, p_cred, p_cred_size)
    return cred_avail;
}

bool aws::credentials::provision::credential_from_kvstore(const char *cred_key, const uint8_t **p_cred, size_t *p_cred_size)
{
    char *cred_value = nullptr;

    /* Key info */
    kv_info_t info;
    auto kv_status = kv_get_info(cred_key, &info);
    if (kv_status != MBED_SUCCESS) {
        printf("kv_get_info: %s failed: %d\r\n", cred_key, MBED_GET_ERROR_CODE(kv_status));
        MBED_ERROR(kv_status, "Fetch credential from KVStore failed");
    }

    size_t actual_size = 0;
    cred_value = new char[info.size];
    kv_status = kv_get(cred_key, cred_value, info.size, &actual_size);
    if (kv_status != MBED_SUCCESS) {
        printf("kv_get: %s failed: %d\r\n", cred_key, MBED_GET_ERROR_CODE(kv_status));
        MBED_ERROR(kv_status, "Fetch credential from KVStore failed");
    }
    if (actual_size != info.size) {
        printf("kv_get: %s failed: expected value size: %d but actual: %d\r\n", cred_key, info.size, actual_size);
        MBED_ERROR(kv_status, "Fetch credential from KVStore failed");
    }

    if (p_cred) {
        *p_cred = (const uint8_t *) cred_value;
    }
    if (p_cred_size) {
        *p_cred_size = actual_size;
    }

    return true;
}
