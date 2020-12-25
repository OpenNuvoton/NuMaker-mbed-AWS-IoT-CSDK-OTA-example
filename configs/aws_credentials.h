/*
 * AWS Certificates
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef AWS_CREDENTIALS_H
#define AWS_CREDENTIALS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Check aws_credentials.c for details. */
extern const char aws_rootCACrt[];
extern const char aws_deviceCrt[];
extern const char aws_devicePubKey[];
extern const char aws_devicePvtKey[];
extern const char aws_codeVerCrt[];

#ifdef __cplusplus
}
#endif

#endif
