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

/* Dispatch host command communicating via USB VCOM
 *
 * WARNING: For mass production, remove this file.
 */

/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */

extern "C" {
    MBED_USED void dispatch_host_command(int);
    MBED_WEAK void print_heap_stats(void);
    MBED_WEAK void print_stack_statistics(void);
}

void dispatch_host_command(int c)
{
    switch (c) {
        case 'h':
            print_heap_stats();
            break;
                
        case 's':
            print_stack_statistics();
            break;
            
        case 'r':
            printf("\r\nSystem reset after 2 secs...\r\n\r\n\r\n");
            ThisThread::sleep_for(2000);
            NVIC_SystemReset();
            break;
    }
}
