/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef SUIT_COSE_H
#define SUIT_COSE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"

typedef enum cose_tag_key {
    COSE_TAG_INVALID    = 0,
    COSE_SIGN_TAGGED    = 98,
    COSE_SIGN1_TAGGED   = 18,
    COSE_ENCRYPT        = 96,
    COSE_ENCRYPT0       = 16,
    COSE_MAC_TAGGED     = 97,
    COSE_MAC0_TAGGED    = 17,
    COSE_KEY            = 101,
    COSE_KEY_SET        = 102,
} cose_tag_key_t;

int32_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key);
cose_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC *signed_cose);
int32_t suit_verify_cose_sign(const UsefulBufC *signed_cose, const char *public_key, UsefulBufC *returned_payload);
int32_t suit_sign_cose_sign1(const UsefulBufC *raw_cbor, const char *private_key, const char *public_key, UsefulBuf *returned_payload);
int32_t suit_verify_cose_sign1(const UsefulBufC *signed_cose, const char *public_key, UsefulBufC *returned_payload);
int32_t suit_verify_cose_mac(const UsefulBufC *signed_cose, const char *public_key, UsefulBufC *returned_payload);
int32_t suit_verify_cose_mac0(const UsefulBufC *signed_cose, const char *public_key, UsefulBufC *returned_payload);


#endif  /* SUIT_COSE_H */

