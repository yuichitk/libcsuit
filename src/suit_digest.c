/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

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
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (hash[i] != digest_bytes_ptr[i]) {
            return SUIT_FAILED_TO_VERIFY;
        }
    }
    return SUIT_SUCCESS;
}

