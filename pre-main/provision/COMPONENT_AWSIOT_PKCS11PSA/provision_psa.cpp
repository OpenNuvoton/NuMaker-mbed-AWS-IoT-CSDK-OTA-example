/*
 * AWS IoT Device SDK for Embedded C 202012.01
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* Standard includes */
#include <stdio.h>
#include <string.h>

/* Mbed includes */
#include "mbed.h"

/* AWS credentials includes */
#include "aws_credentials.h"

/* PKCS11 includes */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "iot_pkcs11_psa_object_management.h"
#include "iot_pkcs11_psa_input_format.h"
#include "provision_psa_utils.h"

/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */
extern "C" {
    MBED_USED void provision(void);
}

static void provision_install_rootca_crt(void);
static void provision_install_device_crt(void);
static void provision_install_device_pubkey(void);
static void provision_install_device_pvtkey(void);
static void provision_install_codever_pubkey(void);

void provision(void)
{
   provision_install_rootca_crt();
   provision_install_device_crt();
   provision_install_device_pubkey();
   provision_install_device_pvtkey();
   provision_install_codever_pubkey();
}

/* Install root CA certificate */
void provision_install_rootca_crt(void)
{
    printf("PROV: Install root CA certificate...\r\n");
    provpsa_install_nonconf((const unsigned char *) aws_rootCACrt,
                            strlen(aws_rootCACrt) + 1,
                            PSA_ROOT_CERTIFICATE_UID);
    printf("PROV: Install root CA certificate...OK\r\n");
}

/* Install device certificate */
void provision_install_device_crt(void)
{
    printf("PROV: Install device certificate...\r\n");
    provpsa_install_nonconf((const unsigned char *) aws_deviceCrt,
                            strlen(aws_deviceCrt) + 1,
                            PSA_DEVICE_CERTIFICATE_UID);
    printf("PROV: Install device certificate...OK\r\n");
}

/* Install device public key */
void provision_install_device_pubkey(void)
{
    printf("PROV: Install device public key...\r\n");
    provpsa_install_pvtpub((const unsigned char *) aws_devicePubKey,
                           strlen(aws_devicePubKey) + 1,
                           PSA_DEVICE_PUBLIC_KEY_ID,
                           false);
    printf("PROV: Install device public key...OK\r\n");
}

/* Install device private key */
void provision_install_device_pvtkey(void)
{
    printf("PROV: Install device private key...\r\n");
    provpsa_install_pvtpub((const unsigned char *) aws_devicePvtKey,
                           strlen(aws_devicePvtKey) + 1,
                           PSA_DEVICE_PRIVATE_KEY_ID,
                           true);
    provpsa_install_pvtpub_extra_nonconf((const unsigned char *) aws_devicePvtKey,
                                         strlen(aws_devicePvtKey) + 1,
                                         PSA_DEVICE_PRIVATE_KEY_ID,
                                         PSA_DEVICE_PRIVATE_KEY_UID);
    printf("PROV: Install device private key...OK\r\n");
}

void provision_install_codever_crt(void)
{
    printf("PROV: Install code verification certificate...\r\n");
    provpsa_install_nonconf((const unsigned char *) aws_codeVerCrt,
                            strlen(aws_codeVerCrt) + 1,
                            PSA_CODE_VERIFICATION_CERTIFICATE_UID);
    printf("PROV: Install code verification certificate...OK\r\n");
}

/* Install code verification public key */
void provision_install_codever_pubkey(void)
{
    printf("PROV: Install code verification public key...\r\n");

    provpsa_install_pubkey_by_crt((const unsigned char *) aws_codeVerCrt,
                                  strlen(aws_codeVerCrt) + 1,
                                  PSA_CODE_VERIFICATION_KEY_ID);
    printf("PROV: Install code verification public key...OK\r\n");
}
