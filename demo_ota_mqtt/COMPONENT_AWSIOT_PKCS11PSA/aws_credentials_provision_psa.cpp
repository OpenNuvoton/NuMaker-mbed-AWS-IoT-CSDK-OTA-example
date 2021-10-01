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

/* Mbed includes */
#include "mbed.h"

/* PSA includes */
#include "psa/crypto.h"
#include "psa/protected_storage.h"

/* PKCS11 includes */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "iot_pkcs11_psa_object_management.h"
#include "iot_pkcs11_psa_input_format.h"

/* This include */
#include "aws_credentials_provision_psa.h"

/* Fetch provisioned credential */
#define PROV_CRED(UID, P_CRED, P_CRED_SIZE)                         \
    static const uint8_t *cred_value_ = nullptr;                    \
    static size_t cred_value_size_ = 0;                             \
    bool cred_avail = true;                                         \
                                                                    \
    if (cred_value_ == nullptr) {                                   \
        cred_avail = cred_from_psa_stor(UID,                        \
                                        &cred_value_,               \
                                        &cred_value_size_);         \
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
    /* Load credential/key from PSA Storage */
    bool cred_from_psa_stor(psa_storage_uid_t uid, const uint8_t **p_cred, size_t *p_cred_size);
}}}

bool aws::credentials::provision::rootCACrt(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(PSA_ROOT_CERTIFICATE_UID, p_cred, p_cred_size);
    return cred_avail;
}

bool aws::credentials::provision::deviceCrt(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(PSA_DEVICE_CERTIFICATE_UID, p_cred, p_cred_size);
    return cred_avail;
}

bool aws::credentials::provision::devicePvtKeyId(psa_key_id_t *key_id)
{
    if (key_id) {
        *key_id = PSA_DEVICE_PRIVATE_KEY_ID;
    }
    
    return true;
}

bool aws::credentials::provision::devicePvtKey(const uint8_t **p_cred, size_t *p_cred_size)
{
    PROV_CRED(PSA_DEVICE_PRIVATE_KEY_UID, p_cred, p_cred_size);
    return cred_avail;
}

bool aws::credentials::provision::cred_from_psa_stor(psa_storage_uid_t uid, const uint8_t **p_cred, size_t *p_cred_size)
{
    psa_status_t rc_psa = PSA_SUCCESS;
    struct psa_storage_info_t cred_key_stor_info;

    rc_psa = psa_ps_get_info(uid, &cred_key_stor_info);
    if (PSA_SUCCESS != rc_psa) {
        printf("psa_ps_get_info(%lld) failed: %d\r\n", uid, rc_psa);
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_UNKNOWN), "Fetch credential from PSA PS failed");
    }

    uint8_t *cred_value = (uint8_t *) malloc(cred_key_stor_info.size);
    size_t cred_value_size = 0;
    rc_psa = psa_ps_get(uid,
                        0,
                        cred_key_stor_info.size,
                        cred_value,
                        &cred_value_size);
    if (PSA_SUCCESS != rc_psa) {
        printf("psa_ps_get(%lld) failed: %d\r\n", uid, rc_psa);
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_UNKNOWN), "Fetch credential from PSA PS failed");
    }

    if (p_cred) {
        *p_cred = cred_value;
    }
    if (p_cred_size) {
        *p_cred_size = cred_value_size;
    }

    return true;
}
