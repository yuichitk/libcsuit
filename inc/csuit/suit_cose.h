/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef SUIT_COSE_H
#define SUIT_COSE_H

#include "csuit/suit_common.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_sign1_sign.h"
#if defined(LIBCSUIT_PSA_CRYPTO_C)
#include "psa/crypto.h"
#else
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#endif /* LIBCSUIT_PSA_CRYPTO_C */

/*!
    \file   suit_cose.h

    \brief  Sign and Verify the COSE.

    SUIT supports only COSE_Sign, COSE_Sign1, COSE_Mac, and COSE_Mac0.
    Currently libcsuit only supports COSE_Sign1 signing and verification.
 */

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




/*!
    \brief      Distinguish the TAG of the COSE binary.

    \param[in]  signed_cose     Pointer and length of COSE signed cbor.

    \return     This returns one of the error codes defined by \ref cose_tag_key_t.
 */
cose_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC *signed_cose);

/*!
    \brief  Generate COSE_Sign1 sined payload.

    \param[in]  raw_cbor            Pointer and length of the target payload.
    \param[in]  key_pair            Pointer of private and public key pair.
    \param[out] returned_payload    Pointer and length of the resulting COSE_Sign1.

    \return     This returns SUIT_SUCCESS, SUIT_ERR_FAILED_TO_VERIFY or SUIT_ERR_FATAL.
 */
suit_err_t suit_sign_cose_sign1(const UsefulBufC raw_cbor, const struct t_cose_key *key_pair, UsefulBuf *returned_payload);

/*!
    \brief  Verify COSE_Sign signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[in]  returned_payload    Pointer and length of the COSE_Sign signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_cose_sign(const UsefulBufC signed_cose, const struct t_cose_key *public_key, UsefulBufC returned_payload);

/*!
    \brief  Verify COSE_Sign1 signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[out] returned_payload    Pointer and length of the COSE_Sign1 signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    COSE_Sign1 structure is like below.
    \code{.unparsed}
    COSE_Sign1 = [
        Headers,
        payload : bstr / nil,
        signature : bstr
    ]
    \endcode

    This function verifies whether the payload correspond to the signature,
    and then extracts payload to returned_payload if success.
 */
suit_err_t suit_verify_cose_sign1(const UsefulBufC signed_cose, const struct t_cose_key *public_key, UsefulBufC returned_payload);

/*!
    \brief  Verify COSE_Mac signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[in]  returned_payload    Pointer and length of the COSE_Mac signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */

suit_err_t suit_verify_cose_mac(const UsefulBufC signed_cose, const struct t_cose_key *public_key, UsefulBufC *returned_payload);

/*!
    \brief  Verify COSE_Mac0 signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[in]  returned_payload    Pointer and length of the COSE_Mac0 signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */
suit_err_t suit_verify_cose_mac0(const UsefulBufC signed_cose, const struct t_cose_key *public_key, UsefulBufC *returned_payload);

/*!
    \brief  Create ES256 key pair

    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer of struct t_cose_key type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
suit_err_t suit_create_es256_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair);

/*!
    \brief  Create ES256 public key

    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer of struct t_cose_key type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
suit_err_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key);

#endif  /* SUIT_COSE_H */

