/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#include <stdio.h>
#include <string.h>
#include "suit_common.h"
#include "suit_digest.h"
#include "openssl/ecdsa.h"

int32_t suit_verify_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len) {
    if (digest_bytes_len != SHA256_DIGEST_LENGTH) {
        return SUIT_UNEXPECTED_ERROR;
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, tgt_ptr, tgt_len);
    SHA256_Final(hash, &sha256);
    return (memcmp(digest_bytes_ptr, hash, SHA256_DIGEST_LENGTH) == 0) ? SUIT_SUCCESS : SUIT_FAILED_TO_VERIFY;
}

