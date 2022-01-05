/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#include "csuit/suit_cose.h"

/*!
    \file   suit_cose.c

    \brief  This implements Sign and Verify the COSE.
 */

/*
    Public function. See suit_cose.h
 */
cose_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC *signed_cose) {
    /* judge authentication object
     * [ COSE_Sign_Tagged, COSE_Sign1_Tagged, COSE_Mac_Tagged, COSE_Mac0_Tagged ]
     */
    cose_tag_key_t result = COSE_TAG_INVALID;
    uint8_t tag0 = ((uint8_t *)signed_cose->ptr)[0];
    uint8_t tag1;
    switch (tag0) {
    case 0xd1: // Tag(17)
        result = COSE_MAC0_TAGGED;
        break;
    case 0xd2: // Tag(18)
        result = COSE_SIGN1_TAGGED;
        break;
    case 0xe8:
        tag1 = ((uint8_t *)signed_cose->ptr)[1];
        switch (tag1) {
        case 0x61: // Tag(97)
            result = COSE_MAC_TAGGED;
            break;
        case 0x62: // Tag(98)
            result = COSE_SIGN_TAGGED;
            break;
        }
    default:
        break;
    }
    return result;
}

#if defined(LIBCSUIT_PSA_CRYPTO_C)
/*
    Public function. See suit_cose.h
 */
suit_err_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t     key_handle = 0;
    psa_status_t         result;
    size_t               public_key_len = 65;

    result = psa_crypto_init();

    if (result != PSA_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    psa_set_key_usage_flags( &key_attributes,
                             PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT );
    psa_set_key_algorithm( &key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256) );
    psa_set_key_type( &key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) );

    result = psa_import_key(&key_attributes,
                            (const unsigned char*) public_key,
                            public_key_len,
                            &key_handle);

    if (result != PSA_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    cose_public_key->k.key_handle = key_handle;
    cose_public_key->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return SUIT_SUCCESS;
}
#else /* LIBCSUIT_PSA_CRYPTO_C */

/*
    \brief      Internal function calls OpenSSL functions to create public key.

    \param[in]  nid                 EC network id.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer and length of the resulting key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */
suit_err_t suit_create_es_public_key(int nid, const char *public_key, struct t_cose_key *cose_public_key) {
    EC_GROUP    *ec_group = NULL;
    EC_KEY      *ec_key = NULL;
    EC_POINT    *ec_point = NULL;
    int         result = 0;

    ec_group = EC_GROUP_new_by_curve_name(nid);
    if (ec_group == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    result = EC_KEY_set_group(ec_key, ec_group);
    if (!result) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    ec_point = EC_POINT_hex2point(ec_group, public_key, ec_point, NULL);
    if (ec_point == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    result = EC_KEY_set_public_key(ec_key, ec_point);
    if (result == 0) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    cose_public_key->k.key_ptr  = ec_key;
    cose_public_key->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;
}

suit_err_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_es_public_key(NID_X9_62_prime256v1, public_key, cose_public_key);
}

suit_err_t suit_create_es384_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_es_public_key(NID_secp384r1, public_key, cose_public_key);
}

suit_err_t suit_create_es521_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_es_public_key(NID_secp521r1, public_key, cose_public_key);
}
#endif /* LIBCSUIT_PSA_CRYPTO_C */

suit_err_t suit_verify_cose_sign1(const UsefulBufC *signed_cose, const struct t_cose_key *public_key, UsefulBufC *returned_payload) {
    suit_err_t result = SUIT_SUCCESS;
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_parameters parameters;
    enum t_cose_err_t cose_result;

    if (public_key == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, *public_key);
    cose_result = t_cose_sign1_verify_detached(&verify_ctx,
                                               *signed_cose,
                                               NULL_Q_USEFUL_BUF_C,
                                               returned_payload,
                                               &parameters);
    if (cose_result != T_COSE_SUCCESS) {
        result = SUIT_ERR_FAILED_TO_VERIFY;
    }
    return result;
}

/*!
    \brief  Distinguish algorithm id from t_cose_key.

    \param[in]  key                 Pointer of the key.
    \param[out] cose_algorithm_id   Pointer of the resulting algorithm id.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    COSE supports ES256, ES384 and ES512 as alrogithm of signature,
    so T_COSE_ALGORITHM_ES256, T_COSE_ALGORITHM_ES384 or T_COSE_ALGORITHM_ES512 will be set to cose_algorithm_id argument if success.
 */
suit_err_t suit_get_algorithm_from_cose_key(const struct t_cose_key *key, int32_t *cose_algorithm_id) {
#if defined(LIBCSUIT_PSA_CRYPTO_C)
    if (key->crypto_lib != T_COSE_CRYPTO_LIB_PSA) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    psa_key_handle_t *key_handle = key->k.key_ptr;
    psa_key_attributes_t key_attributes;
    psa_status_t status = psa_get_key_attributes(*key_handle, &key_attributes);
    if (status != PSA_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    psa_algorithm_t key_alg = psa_get_key_algorithm(&key_attributes);
    switch (key_alg) {
    case PSA_ALG_ECDSA(PSA_ALG_SHA_256):
        *cose_algorithm_id = T_COSE_ALGORITHM_ES256;
        break;
    case PSA_ALG_ECDSA(PSA_ALG_SHA_384):
        *cose_algorithm_id = T_COSE_ALGORITHM_ES384;
        break;
    case PSA_ALG_ECDSA(PSA_ALG_SHA_512):
        *cose_algorithm_id = T_COSE_ALGORITHM_ES512;
        break;
    default:
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
#else /* !LIBCSUIT_PSA_CRYPTO_C */
    if (key->crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    const EC_KEY *key_ptr = key->k.key_ptr;
    if (key_ptr == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    const EC_GROUP *ec_group = EC_KEY_get0_group(key_ptr);
    if (ec_group == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    int nid = EC_GROUP_get_curve_name(ec_group);
    switch (nid) {
    case NID_X9_62_prime256v1:
        *cose_algorithm_id = T_COSE_ALGORITHM_ES256;
        break;
    case NID_secp384r1:
        *cose_algorithm_id = T_COSE_ALGORITHM_ES384;
        break;
    case NID_secp521r1:
        *cose_algorithm_id = T_COSE_ALGORITHM_ES512;
        break;
    default:
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
#endif
    return SUIT_SUCCESS;
}

suit_err_t suit_sign_cose_sign1(const UsefulBufC *raw_cbor, const struct t_cose_key *key_pair, UsefulBuf *returned_payload) {
    // Create cose signed buffer.
    int32_t cose_algorithm_id;
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;
    UsefulBufC tmp_signed_cose;
    UsefulBuf_MAKE_STACK_UB(signed_cose_buffer, 1024);

    suit_err_t result = suit_get_algorithm_from_cose_key(key_pair, &cose_algorithm_id);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
    case T_COSE_ALGORITHM_ES384:
    case T_COSE_ALGORITHM_ES512:
        break;
    default:
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, *key_pair, NULL_Q_USEFUL_BUF_C);
    cose_result = t_cose_sign1_sign_detached(&sign_ctx, NULL_Q_USEFUL_BUF_C, *raw_cbor, signed_cose_buffer, &tmp_signed_cose);
    if (cose_result != T_COSE_SUCCESS) {
        return SUIT_ERR_FATAL;
    }
    memcpy(returned_payload->ptr, tmp_signed_cose.ptr, tmp_signed_cose.len);
    returned_payload->len = tmp_signed_cose.len;
    return SUIT_SUCCESS;
}

