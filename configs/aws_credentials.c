/*
 * AWS Certificates
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */


#include "aws_credentials.h"

/*
 * PEM-encoded root CA certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char aws_rootCACrt[] = "-----BEGIN CERTIFICATE-----\n"
"...\n"
"...\n"
"...\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded device certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char aws_deviceCrt[] = "-----BEGIN CERTIFICATE-----\n"
"...\n"
"...\n"
"...\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded device public key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN PUBLIC KEY-----\n"
 * "...base64 data...\n"
 * "-----END PUBLIC KEY-----"
 */
const char aws_devicePubKey[] = "-----BEGIN PUBLIC KEY-----\n"
"...\n"
"...\n"
"...\n"
"-----END PUBLIC KEY-----";

/*
 * PEM-encoded device private key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN RSA PRIVATE KEY-----\n"
 * "...base64 data...\n"
 * "-----END RSA PRIVATE KEY-----";
 */
const char aws_devicePvtKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
"...\n"
"...\n"
"...\n"
"-----END RSA PRIVATE KEY-----";

/*
 * PEM-encoded code verification certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char aws_codeVerCrt[] = "-----BEGIN CERTIFICATE-----\n"
"...\n"
"...\n"
"...\n"
"-----END CERTIFICATE-----";
