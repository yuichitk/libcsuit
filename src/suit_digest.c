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

#if defined(LIBCSUIT_PSA_CRYPTO_C)
suit_err_t suit_generate_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len) {
    psa_status_t status;
    size_t real_hash_size;
    psa_hash_operation_t sha256_psa = PSA_HASH_OPERATION_INIT;

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
        return( SUIT_ERR_FAILED_TO_VERIFY );

    status = psa_hash_setup( &sha256_psa, PSA_ALG_SHA_256 );
    if( status != PSA_SUCCESS )
        return( SUIT_ERR_FAILED_TO_VERIFY );

    status = psa_hash_update( &sha256_psa, tgt_ptr, tgt_len );
    if( status != PSA_SUCCESS )
        return( SUIT_ERR_FAILED_TO_VERIFY );

    status = psa_hash_finish( &sha256_psa, digest_bytes_ptr, digest_bytes_len, &real_hash_size );
    if( status != PSA_SUCCESS )
        return( SUIT_ERR_FAILED_TO_VERIFY );

    if(real_hash_size != SHA256_DIGEST_LENGTH)
        return( SUIT_ERR_FAILED_TO_VERIFY );

    return SUIT_SUCCESS;
}
#else
suit_err_t suit_generate_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, uint8_t *digest_bytes_ptr, const size_t digest_bytes_len) {
    int result;
    SHA256_CTX sha256;
    result = SHA256_Init(&sha256);
    if (!result) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    result = SHA256_Update(&sha256, tgt_ptr, tgt_len);
    if (!result) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    result = SHA256_Final(digest_bytes_ptr, &sha256);
    return (result) ? SUIT_SUCCESS : SUIT_ERR_FAILED_TO_VERIFY;
}
#endif /* LIBCSUIT_PSA_CRYPTO_C */

suit_err_t suit_verify_sha256(const uint8_t *tgt_ptr, const size_t tgt_len, const uint8_t *digest_bytes_ptr, const size_t digest_bytes_len) {
    if (digest_bytes_len != SHA256_DIGEST_LENGTH) {
        return SUIT_ERR_FATAL;
    }
    uint8_t hash[SHA256_DIGEST_WORK_SPACE_LENGTH];
    suit_err_t result = suit_generate_sha256(tgt_ptr, tgt_len, hash, SHA256_DIGEST_WORK_SPACE_LENGTH);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    return (memcmp(digest_bytes_ptr, hash, SHA256_DIGEST_LENGTH) == 0) ? SUIT_SUCCESS : SUIT_ERR_FAILED_TO_VERIFY;
}

