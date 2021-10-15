/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef SUIT_DIGEST_H
#define SUIT_DIGEST_H

#include "suit_common.h"
struct suit_digest;
struct suit_buf;

#if defined(LIBCSUIT_PSA_CRYPTO_C)
#include "psa/crypto.h"
#define SHA256_DIGEST_LENGTH 32
#include "mbedtls/md.h"
#define SHA256_DIGEST_WORK_SPACE_LENGTH MBEDTLS_MD_MAX_SIZE
#else /* LIBCSUIT_PSA_CRYPTO_C */
#include "openssl/sha.h"
#define SHA256_DIGEST_WORK_SPACE_LENGTH SHA256_DIGEST_LENGTH
#endif /* LIBCSUIT_PSA_CRYPTO_C */

/*!
    \file   suit_digest.h

    \brief  SHA-2 and SHA-3 functions to generate and verify the hash
 */

/*!
    \brief      Generate SHA-224 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha224(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA-256 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    This function generates SHA-256 hash to the digest_bytes_ptr.
 */
suit_err_t suit_generate_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA-384 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha384(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA-512 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha512(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA3-224 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha3_224(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA3-256 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha3_256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA3-384 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha3_384(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Generate SHA3-512 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_generate_sha3_512(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA-224 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha224(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA-256 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    This verifies the hash of the payload, specified by tgt_ptr and tgt_len,
    matches the input digest, specified by digest_bytes_ptr and digest_bytes_len.
 */
suit_err_t suit_verify_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA-384 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha384(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA-512 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha512(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA3-224 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha3_224(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA3-256 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha3_256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA3-384 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha3_384(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

/*!
    \brief      Verify SHA3-512 digest

    \param[in]  tgt_ptr             Pointer of the payload to be taken hash.
    \param[in]  tgt_len             Length of the payload.
    \param[out] digest_bytes_ptr    Pointer of the buffer of generated digest to be placed.
    \param[in]  digest_bytes_len    Length of the digest buffer.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_sha3_512(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len);

suit_err_t suit_verify_digest(struct suit_buf *buf, struct suit_digest *digest);
suit_err_t suit_verify_digest(struct suit_buf *buf, struct suit_digest *digest);
suit_err_t suit_generate_digest(const uint8_t *ptr, const size_t len, struct suit_digest *digest);

#endif /* SUIT_DIGEST_H */

