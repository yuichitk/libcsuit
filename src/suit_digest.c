/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#if !defined(LIBCSUIT_PSA_CRYPTO_C)

#include <stdio.h>
#include <string.h>
#include "suit_common.h"
#include "suit_digest.h"
#include "openssl/ecdsa.h"

int32_t suit_generate_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr) {
    int result;
    SHA256_CTX sha256;
    result = SHA256_Init(&sha256);
    if (!result) {
        return SUIT_FAILED_TO_VERIFY;
    }
    result = SHA256_Update(&sha256, tgt_ptr, tgt_len);
    if (!result) {
        return SUIT_FAILED_TO_VERIFY;
    }
    result = SHA256_Final(digest_bytes_ptr, &sha256);
    return (result) ? SUIT_SUCCESS : SUIT_FAILED_TO_VERIFY;
}

int32_t suit_verify_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len) {
    if (digest_bytes_len != SHA256_DIGEST_LENGTH) {
        return SUIT_FATAL_ERROR;
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    int32_t result = suit_generate_sha256(tgt_ptr, tgt_len, hash);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    return (memcmp(digest_bytes_ptr, hash, SHA256_DIGEST_LENGTH) == 0) ? SUIT_SUCCESS : SUIT_FAILED_TO_VERIFY;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
