# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-client-for-aws
    INTERFACE
        .
)

target_sources(mbed-client-for-aws
    INTERFACE
        provision.cpp
)
