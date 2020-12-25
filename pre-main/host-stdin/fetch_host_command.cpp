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

/* Fetch host command communicating via USB VCOM
 *
 * WARNING: For mass production, remove this file.
 */

/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */

extern "C" {
    MBED_USED int fetch_host_command(void);
}

int fetch_host_command(void)
{
    struct pollfd fds[1];

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;    
    int rc = poll(fds, sizeof(fds)/sizeof(fds[0]), 0);
    if ((rc > 0) && (fds[0].revents & POLLIN)) {
        return getchar();
    } else {
        return -1;
    }
}
