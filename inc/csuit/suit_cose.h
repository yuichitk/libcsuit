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
#include "openssl/evp.h"
#include "openssl/ec.h"
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
cose_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC signed_cose);

typedef struct suit_key {
    const unsigned char *private_key;
    size_t private_key_len;
    const unsigned char *public_key;
    size_t public_key_len;
    int cose_algorithm_id;
    struct t_cose_key cose_key;
} suit_key_t;

typedef struct suit_mechanism {
    int cose_tag; // COSE_Sign1, COSE_Sign, COSE_Encrypt0, COSE_Encrypt, etc.
    suit_key_t keys[SUIT_MAX_KEY_NUM];
} suit_mechanism_t;

/*!
    \brief  Generate COSE_Sign1 sined payload.

    \param[in]  raw_cbor            Pointer and length of the target payload.
    \param[in]  key_pair            Pointer of private and public key pair.
    \param[out] returned_payload    Pointer and length of the resulting COSE_Sign1.

    \return     This returns SUIT_SUCCESS, SUIT_ERR_FAILED_TO_VERIFY or SUIT_ERR_FATAL.
 */
suit_err_t suit_sign_cose_sign1(const UsefulBufC raw_cbor, const suit_key_t *key_pair, UsefulBuf *returned_payload);

/*!
    \brief  Verify COSE_Sign signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[in]  returned_payload    Pointer and length of the COSE_Sign signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    NOTE: Currently not implemented.
 */
suit_err_t suit_verify_cose_sign(const UsefulBufC signed_cose, const suit_key_t *public_key, UsefulBufC returned_payload);

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
suit_err_t suit_verify_cose_sign1(const UsefulBufC signed_cose, const suit_key_t *public_key, UsefulBufC returned_payload);

/*!
    \brief  Verify COSE_Mac signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[in]  returned_payload    Pointer and length of the COSE_Mac signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */

suit_err_t suit_verify_cose_mac(const UsefulBufC signed_cose, const suit_key_t *public_key, UsefulBufC *returned_payload);

/*!
    \brief  Verify COSE_Mac0 signed payload.

    \param[in]  signed_cose         Pointer and length of the target signed payload.
    \param[in]  public_key          Pointer of public key.
    \param[in]  returned_payload    Pointer and length of the COSE_Mac0 signed target payload.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */
suit_err_t suit_verify_cose_mac0(const UsefulBufC signed_cose, const suit_key_t *public_key, UsefulBufC *returned_payload);

#endif  /* SUIT_COSE_H */

