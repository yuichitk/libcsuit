/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef SUIT_DIGEST_H
#define SUIT_DIGEST_H

#if !defined(LIBCSUIT_PSA_CRYPTO_C)

#include <stdio.h>
#include <string.h>
#include "openssl/sha.h"


int32_t suit_generate_sha224(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha384(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha512(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha3_224(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha3_256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha3_384(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);
int32_t suit_generate_sha3_512(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr);

int32_t suit_verify_sha224(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha384(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha512(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha3_224(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha3_256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha3_384(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);
int32_t suit_verify_sha3_512(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

#endif /* LIBCSUIT_PSA_CRYPTO_C */

#endif /* SUIT_DIGEST_H */

