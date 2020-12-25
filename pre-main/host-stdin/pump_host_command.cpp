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

#include "mbed.h"

/* Support host command communicating via USB VCOM
 *
 * WARNING: For mass production, remove this file.
 */
 
/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */

extern "C" {
    MBED_USED void pump_host_command(void);
    MBED_WEAK int fetch_host_command(void);
    MBED_WEAK void dispatch_host_command(int);
}

void pump_host_command(void)
{
    if (fetch_host_command && dispatch_host_command) {
        dispatch_host_command(fetch_host_command());
    }
}
