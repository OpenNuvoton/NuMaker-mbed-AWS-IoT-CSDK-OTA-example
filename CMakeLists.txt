# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.19.0 FATAL_ERROR)

set(MBED_PATH ${CMAKE_CURRENT_SOURCE_DIR}/mbed-os CACHE INTERNAL "")
set(MBED_CONFIG_PATH ${CMAKE_CURRENT_BINARY_DIR} CACHE INTERNAL "")
set(APP_TARGET NuMaker-mbed-AWS-IoT-CSDK-OTA-example)

include(${MBED_PATH}/tools/cmake/app.cmake)

add_compile_definitions(MBEDTLS_THREADING_C)
add_compile_definitions(MBEDTLS_THREADING_ALT)
add_compile_definitions(APPLICATION_ADDR=0x00)
add_compile_definitions(APPLICATION_SIZE=0x80000)

add_subdirectory(${MBED_PATH})
add_subdirectory(mbed-client-for-aws)

add_executable(${APP_TARGET})

mbed_configure_app_target(${APP_TARGET})

project(${APP_TARGET})

target_include_directories(${APP_TARGET}
    PRIVATE
        .
        configs
        demo_ota_mqtt
)

target_sources(${APP_TARGET}
    PRIVATE
        configs/aws_credentials.c
        demo_ota_mqtt/ota_demo_core_mqtt.cpp
        demo_ota_mqtt/aws_credentials_provision.cpp
        demo_ota_mqtt/mqtt_subscription_manager.c
        pre-main/mbed_main.cpp
        pre-main/host-stdin/dispatch_host_command.cpp
        pre-main/host-stdin/fetch_host_command.cpp
        pre-main/host-stdin/mem_stats.cpp
        pre-main/host-stdin/pump_host_command.cpp
        pre-main/provision/provision.cpp
)

if("NUVOTON" IN_LIST MBED_TARGET_LABELS)
    target_sources(${APP_TARGET}
        PRIVATE
            "targets/TARGET_NUVOTON/platform_entropy.cpp"
    )
endif()

target_link_libraries(${APP_TARGET}
    PRIVATE
        mbed-client-for-aws
        mbed-os
        mbed-storage-kvstore
        mbed-mbedtls
        mbed-netsocket
        mbed-wifi
)

mbed_set_post_build(${APP_TARGET})

option(VERBOSE_BUILD "Have a verbose build process")
if(VERBOSE_BUILD)
    set(CMAKE_VERBOSE_MAKEFILE ON)
endif()
