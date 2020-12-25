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

#include "mbed.h"

/* Run pre-main tasks via mbed_main()
 *
 * In Mbed OS boot sequence, mbed_main(), designed for user application override, is run
 * before main(). We use it to run the following tasks:
 *
 * 1. Simulate provision process for development
 * 2. Set up event queue for dispatching host command
 *
 * WARNING: For mass production, remove this file.
 */

/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */

extern "C" {
    MBED_USED void mbed_main(void);
    MBED_WEAK void provision(void);
    MBED_WEAK void pump_host_command(void);
}

void mbed_main(void)
{
    provision();
    /* Spare memory if event queue is unnecessary */
    if (pump_host_command) {
        mbed_event_queue()->call_every(2000, pump_host_command);
    }
}
