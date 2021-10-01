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

#ifndef AWS_CREDENTIALS_PROVISION_KVSTORE_H
#define AWS_CREDENTIALS_PROVISION_KVSTORE_H

#include <stdint.h>

namespace aws {
namespace credentials {
namespace provision {
    bool rootCACrt(const uint8_t **p_cred, size_t *p_cred_size);
    bool deviceCrt(const uint8_t **p_cred, size_t *p_cred_size);
    bool devicePubKey(const uint8_t **p_cred, size_t *p_cred_size);
    bool devicePvtKey(const uint8_t **p_cred, size_t *p_cred_size);
    bool codeVerKey(const uint8_t **p_cred, size_t *p_cred_size);
}}}

#endif /* ifndef IOT_PLATFORM_TYPES_TEMPLATE_H_ */
