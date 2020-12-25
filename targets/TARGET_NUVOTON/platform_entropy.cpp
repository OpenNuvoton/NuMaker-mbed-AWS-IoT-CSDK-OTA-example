/* 
 * Copyright (c) 2019 Nuvoton Technology Corporation
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

#if !DEVICE_TRNG && !TARGET_PSA
 
#include "mbed.h"
#include "mbedtls/config.h"

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

/* Support entropy source with EADC seeded PRNG on non-PSA targets without TRNG
 *
 * Follow the steps below to replace TRNG with EADC seeded PRNG:
 *
 * 1. Seed PRNG with EADC band gap
 * 2. Define MBEDTLS_ENTROPY_HARDWARE_ALT and provide custom mbedtls_hardware_poll(...)
 *
 * Reference configuration in mbed_app.json:
 *
 * For Pelion/mbedtls:
 *
 *  "target.macros_add": [
 *      "MBEDTLS_USER_CONFIG_FILE=\"mbedTLSConfig_mbedOS.h\"", 
 *      "MBEDTLS_ENTROPY_HARDWARE_ALT"
 *  ],
 *
 * For non-Pelion/mbedtls:
 *
 *  "target.macros_add": [
 *      "MBEDTLS_ENTROPY_HARDWARE_ALT"
 *  ],
 *
 * For both Pelion/non-Pelion (skip when done in targets.json):
 *
 *  "target.device_has_remove": ["TRNG"],
 *
 * WARNING: If the security level of EADC seeded PRNG cannot meet requirements, replace it with another entropy source.
 */

#include "crypto-misc.h"

extern "C" {
    int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);
}

/* Support EADC band gap
 *
 * Mbed OS defines analog-in HAL for normal purposes, but EADC band gap is not defined.
 * To avoid EADC code conflict and fit into existent analog-in HAL, we:
 *
 * 1. Hijack AnalogIn driver to involve analog-in HAL protection and EADC initialization.
 *    This needs one dedicated EADC pin EADC_AUX_PINNAME.
 * 2. Run EADC band gap conversion, with EADC module already initialized via above. This needs
 *    one dedicated sample module and one dedicated channel.
 */

#if TARGET_NUC472
    #define EADC_AUX_PINNAME        A0
    #define EADC_BANDGAP_SMPLMOD    7
    #define EADC_BANDGAP_CHN        8
    #define PRNG_KEYSIZE_ID         PRNG_KEY_SIZE_128
    #define PRNG_KEYSIZE            16
#elif TARGET_M480
    #define EADC_AUX_PINNAME        A0
    #define EADC_BANDGAP_SMPLMOD    16
    #define EADC_BANDGAP_CHN        16
    #define PRNG_KEYSIZE_ID         PRNG_KEY_SIZE_128
    #define PRNG_KEYSIZE            16
#else
    #error("Target not support")
#endif

#if ( (MBED_MAJOR_VERSION == 6) && (TARGET_M480) )
    #define PRNG_OBJ CRPT
    #define NU_PRNG_ENABLE_INT()    PRNG_ENABLE_INT(CRPT)
    #define NU_PRNG_Open(a, b, c)   PRNG_Open(CRPT, a, b, c)
    #define NU_PRNG_DISABLE_INT()   PRNG_DISABLE_INT(CRPT)
    #define NU_PRNG_Start()         PRNG_Start(CRPT)
    #define NU_PRNG_Read(a)         PRNG_Read(CRPT, a)
#else
    #define PRNG_OBJ
    #define NU_PRNG_ENABLE_INT()    PRNG_ENABLE_INT()
    #define NU_PRNG_Open(a, b, c)   PRNG_Open(a, b, c)
    #define NU_PRNG_DISABLE_INT()   PRNG_DISABLE_INT()
    #define NU_PRNG_Start()         PRNG_Start()
    #define NU_PRNG_Read(a)         PRNG_Read(a)
#endif

class NuBandGap : public mbed::AnalogIn {
public:
    NuBandGap();
    ~NuBandGap();

    /* Generate bitstream based on EADC band gap 
     *
     * @returns 1/0 bitstream
     */
    uint16_t read_bitstream();
};

class NuEADCSeedPRNG : private mbed::NonCopyable<NuEADCSeedPRNG>
{
public:
    NuEADCSeedPRNG();
    ~NuEADCSeedPRNG();

    /* Get random data
     *
     * @param output    The pointer to an output array
     * @param len       The size of output data, to avoid buffer overwrite
     * @param olen      The length of generated data
     */
    int get_bytes(unsigned char *output, size_t len, size_t *olen);

private:
    NuBandGap band_gap;
};


int mbedtls_hardware_poll(MBED_UNUSED void *data, unsigned char *output, size_t len, size_t *olen)
{
    static NuEADCSeedPRNG eadc_seed_prng;

    return eadc_seed_prng.get_bytes(output, len, olen);
}

NuBandGap::NuBandGap() : mbed::AnalogIn(EADC_AUX_PINNAME)
{
    EADC_T *eadc_base = (EADC_T *) EADC_BASE;

    EADC_ConfigSampleModule(eadc_base, EADC_BANDGAP_SMPLMOD, EADC_SOFTWARE_TRIGGER, EADC_BANDGAP_CHN);
}

NuBandGap::~NuBandGap()
{
}

uint16_t NuBandGap::read_bitstream()
{
    uint16_t one_or_zero;

    lock();

    EADC_T *eadc_base = (EADC_T *) EADC_BASE;

    EADC_START_CONV(eadc_base, 1 << EADC_BANDGAP_SMPLMOD);
    while (EADC_GET_DATA_VALID_FLAG(eadc_base, 1 << EADC_BANDGAP_SMPLMOD) != (1 << EADC_BANDGAP_SMPLMOD));
    uint16_t conv_res_12 = EADC_GET_CONV_DATA(eadc_base, EADC_BANDGAP_SMPLMOD);

    /* 1 as number of 'one' is odd; 0 otherwise */
    unsigned i;
    uint16_t count_one = 0;
    for (i = 0; i < 12; i ++) {
        if (conv_res_12 & 1) {
            count_one ++;
        }
        conv_res_12 >>= 1;
    }
    one_or_zero = count_one & 1;

    unlock();
    
    return one_or_zero;
}

NuEADCSeedPRNG::NuEADCSeedPRNG()
{
    crypto_init();
    NU_PRNG_ENABLE_INT();

    uint32_t seed = 0;
    unsigned i = 32;

    /* Get seed from EADC band gap */
    while (i --) {
        seed <<= 1;
        seed |= band_gap.read_bitstream();
    }

    /* PRNG reload seed */
    NU_PRNG_Open(PRNG_KEYSIZE_ID, 1, seed);
}

NuEADCSeedPRNG::~NuEADCSeedPRNG()
{
    NU_PRNG_DISABLE_INT();
    crypto_uninit();
}

int NuEADCSeedPRNG::get_bytes(unsigned char *output, size_t len, size_t *olen)
{
    /* Check argument validity */
    if (!output && len) {
        return -1;
    }

    unsigned char *output_ind = output;
    size_t rmn = len;
    uint32_t rand_data[PRNG_KEYSIZE / sizeof(uint32_t)];
    while (rmn) {
        crypto_prng_prestart();
        NU_PRNG_Start();
        crypto_prng_wait();

        NU_PRNG_Read(rand_data);

        size_t n = (rmn >= PRNG_KEYSIZE) ? PRNG_KEYSIZE : rmn;
        memcpy(output_ind, rand_data, n);
        
        output_ind += n;
        rmn -= n;
    }

    if (olen) {
        *olen = len;
    }

    return 0;
}

#else

/* Support entropy source with mbedtls NV seed on non-PSA targets without TRNG
 *
 * Follow the steps below to replace TRNG with mbedtls NV seed:
 *
 * 1. Define MBEDTLS_ENTROPY_NV_SEED
 * 2. Define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO/MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO and provide custom mbedtls_nv_seed_read(...)/mbedtls_nv_seed_write(...).
 * 3. Don't define MBEDTLS_PSA_INJECT_ENTROPY. Meet mbedtls_psa_inject_entropy(...) undefined and then provide custom one, which must be compatible with mbedtls_nv_seed_read(...)/mbedtls_nv_seed_write(...) above.
 * 4. For development, simulating partial provision process, inject entropy seed via mbedtls_psa_inject_entropy(...) pre-main.
 *
 * Reference configuration in mbed_app.json:
 *
 * For Pelion/mbedtls, don't define MBEDTLS_ENTROPY_NV_SEED because it has defined in:
 * https://github.com/ARMmbed/mbed-cloud-client/blob/master/mbed-client-pal/Configs/mbedTLS/mbedTLSConfig_mbedOS_SW_TRNG.h
 * 
 *  "target.macros_add": [
 *      "MBEDTLS_USER_CONFIG_FILE=\"mbedTLSConfig_mbedOS_SW_TRNG.h\"", 
 *      "PAL_USE_HW_TRNG=0",
 *      "MBEDTLS_PLATFORM_NV_SEED_READ_MACRO=mbedtls_platform_seed_read",
 *      "MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO=mbedtls_platform_seed_write"
 *  ],
 *
 * For non-Pelion/mbedtls:
 *
 *  "target.macros_add": [
 *      "MBEDTLS_ENTROPY_NV_SEED",
 *      "MBEDTLS_PLATFORM_NV_SEED_READ_MACRO=mbedtls_platform_seed_read",
 *      "MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO=mbedtls_platform_seed_write"
 *  ],
 *
 * For both Pelion/non-Pelion (skip when done in targets.json):
 *
 *  "target.device_has_remove": ["TRNG"],
 *
 * WARNING: The injection of mbedtls NV seed pre-main is only for development. Run provision process for mass production.
 */

#include "entropy_poll.h"
#include "psa/crypto.h"
#include "KVStore.h"
#include "TDBStore.h"
#include "KVMap.h"
#include "kv_config.h"

extern "C" {
    psa_status_t mbedtls_psa_inject_entropy(const uint8_t *seed, size_t seed_size);
    int mbedtls_platform_seed_read(unsigned char *buf, size_t buf_len);
    int mbedtls_platform_seed_write(unsigned char *buf, size_t buf_len);
}

/* Requirement of seed size
 *
 * 1. >= MBEDTLS_ENTROPY_MIN_PLATFORM
 * 2. >= MBEDTLS_ENTROPY_BLOCK_SIZE
 * 3. <= MBEDTLS_ENTROPY_MAX_SEED_SIZE
 */
#define SEED_SIZE       64
MBED_STATIC_ASSERT(SEED_SIZE >= MBEDTLS_ENTROPY_MIN_PLATFORM, "Seed size must be larger than or equal to MBEDTLS_ENTROPY_MIN_PLATFORM");
MBED_STATIC_ASSERT(SEED_SIZE >= MBEDTLS_ENTROPY_BLOCK_SIZE, "Seed size must be larger than or equal to MBEDTLS_ENTROPY_BLOCK_SIZE");
MBED_STATIC_ASSERT(SEED_SIZE <= MBEDTLS_ENTROPY_MAX_SEED_SIZE, "Seed size must be smaller than or equal to MBEDTLS_ENTROPY_MAX_SEED_SIZE");

/* Seed key name in kvstore */
#define KV_KEY_SEED         "seed"

/* Inject an initial entropy seed for the random generator into secure storage
 *
 * See reference below for its prototype: 
 * https://github.com/ARMmbed/mbed-os/blob/master/features/mbedtls/mbed-crypto/inc/psa/crypto_extra.h
 */
psa_status_t mbedtls_psa_inject_entropy(const uint8_t *seed, size_t seed_size)
{
    /* Check seed size requirement */
    if ((( seed_size < MBEDTLS_ENTROPY_MIN_PLATFORM) || (seed_size < MBEDTLS_ENTROPY_BLOCK_SIZE)) ||
        (seed_size > MBEDTLS_ENTROPY_MAX_SEED_SIZE)) {
            return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Get kvstore internal storage where seed is injected */
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);
    if (inner_store == NULL) {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    /* Check if seed has injected */
    KVStore::info_t kv_info;
    int kv_status = inner_store->get_info(KV_KEY_SEED, &kv_info);
    if (kv_status == MBED_SUCCESS) {
        return PSA_ERROR_NOT_PERMITTED;
    } else if (kv_status == MBED_ERROR_ITEM_NOT_FOUND) {
        /* No seed injected, inject it below */
    } else {
        return PSA_ERROR_STORAGE_FAILURE;
    }

    /* Inject seed into kvstore internal storage */
    kv_status = inner_store->set(KV_KEY_SEED, seed, seed_size, 0);
    if (kv_status == MBED_SUCCESS) {
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_STORAGE_FAILURE;
    }
}

int mbedtls_platform_seed_read(unsigned char *buf, size_t buf_len)
{
    /* Get kvstore internal storage where seed is injected */
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);
    if (inner_store == NULL) {
        return -1;
    }

    /* Read seed from kvstore internal storage */
    size_t actual_size = 0;
    int kv_status = inner_store->get(KV_KEY_SEED, buf, buf_len, &actual_size, 0);
    if (kv_status != MBED_SUCCESS || actual_size != buf_len) {
        return -1;
    } else {
        return buf_len;
    }
}

int mbedtls_platform_seed_write(unsigned char *buf, size_t buf_len)
{
    /* Get kvstore internal storage where seed is injected */
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);
    if (inner_store == NULL) {
        return -1;
    }

    /* Write seed into kvstore internal storage */
    int kv_status = inner_store->set(KV_KEY_SEED, buf, buf_len, 0);
    if (kv_status != MBED_SUCCESS) {
        return -1;
    } else {
        return buf_len;
    }
}

#endif /* #if defined(MBEDTLS_ENTROPY_HARDWARE_ALT) */

#endif /* !DEVICE_TRNG && !TARGET_PSA */
