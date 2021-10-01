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

#if (MBED_HEAP_STATS_ENABLED) || (MBED_STACK_STATS_ENABLED)
/* Measure memory footprint */
#include "mbed_stats.h"
/* Fix up the compilation on AMRCC for PRIu32 */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

/* Support memory footprint */

/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */

extern "C" {
#if (MBED_HEAP_STATS_ENABLED)
    MBED_USED void print_heap_stats(void);
#endif
#if (MBED_STACK_STATS_ENABLED)
    MBED_USED void print_stack_statistics();
#endif
}

extern Mutex log_mutex;

#if (MBED_HEAP_STATS_ENABLED)
void print_heap_stats(void)
{
    log_mutex.lock();
    mbed_stats_heap_t stats;
    mbed_stats_heap_get(&stats);
    printf("** MBED HEAP STATS **\n");
    printf("**** current_size   : %" PRIu32 "\n", stats.current_size);
    printf("**** max_size       : %" PRIu32 "\n", stats.max_size);
    printf("**** reserved_size  : %" PRIu32 "\n", stats.reserved_size);
    printf("*****************************\n\n");
    log_mutex.unlock();
}
#endif  // MBED_HEAP_STATS_ENABLED

#if (MBED_STACK_STATS_ENABLED)
void print_stack_statistics()
{
    log_mutex.lock();
    printf("** MBED THREAD STACK STATS **\n");
    int cnt = osThreadGetCount();
    mbed_stats_stack_t *stats = (mbed_stats_stack_t*) malloc(cnt * sizeof(mbed_stats_stack_t));

    if (stats) {
        cnt = mbed_stats_stack_get_each(stats, cnt);
        for (int i = 0; i < cnt; i++) {
            printf("Thread: 0x%" PRIx32 ", Stack size: %" PRIu32 ", Max stack: %" PRIu32 "\r\n", stats[i].thread_id, stats[i].reserved_size, stats[i].max_size);
        }

        free(stats);
    }
    printf("*****************************\n\n");
    log_mutex.unlock();
}
#endif  // MBED_STACK_STATS_ENABLED
