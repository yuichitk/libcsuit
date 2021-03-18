/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#include "suit_cose.h"
#include "suit_common.h"

#if defined(LIBCSUIT_PSA_CRYPTO_C)

cose_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC *signed_cose) {
    /* judge authentication object
     * [ COSE_Sign_Tagged, COSE_Sign1_Tagged, COSE_Mac_Tagged, COSE_Mac0_Tagged ]
     */
    cose_tag_key_t result = COSE_TAG_INVALID;
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&context, *signed_cose, QCBOR_DECODE_MODE_NORMAL);
    uint64_t puTags[QCBOR_MAX_TAGS_PER_ITEM];
    QCBORTagListOut out = {0, QCBOR_MAX_TAGS_PER_ITEM, puTags};
    error = QCBORDecode_GetNextWithTags(&context, &item, &out);
    if (error != QCBOR_SUCCESS) {
        suit_debug_print(&context, &item, "suit_judge_cose_tag", QCBOR_TYPE_ANY);
        goto out;
    }
    if (out.uNumUsed == 0) {
        suit_debug_print(&context, &item, "suit_judge_cose_tag(NO TAG FOUND)", QCBOR_TYPE_ANY);
        goto out;
    }
    switch (puTags[0]) {
        case COSE_SIGN_TAGGED:
        case COSE_SIGN1_TAGGED:
        case COSE_MAC_TAGGED:
        case COSE_MAC0_TAGGED:
            result = puTags[0];
            break;
    }
out:
    error = QCBORDecode_Finish(&context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key) 
{
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t     key_handle = 0;
    psa_status_t         result;
    size_t               public_key_len = 65;

    result = psa_crypto_init();

    if(result != PSA_SUCCESS)
        return( EXIT_FAILURE );

    psa_set_key_usage_flags( &key_attributes,
                             PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT );
    psa_set_key_algorithm( &key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256) );
    psa_set_key_type( &key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) );

    /*
     psa_key_type_t       key_type;
     psa_algorithm_t      key_alg;
     key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1);
     key_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
     psa_set_key_usage_flags( &key_attributes, PSA_KEY_USAGE_VERIFY_HASH );
     psa_set_key_algorithm( &key_attributes, key_alg );
     psa_set_key_type( &key_attributes, key_type );
    */

    result = psa_import_key(&key_attributes,
                            public_key,
                            public_key_len,
                            &key_handle);

    if (result != PSA_SUCCESS)
        return( EXIT_FAILURE );

    cose_public_key->k.key_handle = key_handle;
    cose_public_key->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return( SUIT_SUCCESS );
}
#else

int32_t suit_create_es256_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    EC_GROUP    *ec_group = NULL;
    EC_KEY      *ec_key = NULL;
    BIGNUM      *private_key_bn = NULL;
    EC_POINT    *pub_key_point = NULL;
    int         result = 0;

    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_group == NULL) {
        return SUIT_FATAL_ERROR;
    }
    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        return SUIT_FATAL_ERROR;
    }
    result = EC_KEY_set_group(ec_key, ec_group);
    if (!result) {
        return SUIT_FATAL_ERROR;
    }
    private_key_bn = BN_new();
    if (private_key_bn == NULL) {
        return SUIT_FATAL_ERROR;
    }
    BN_zero(private_key_bn);
    result = BN_hex2bn(&private_key_bn, private_key);
    if(private_key_bn == 0) {
        return SUIT_FATAL_ERROR;
    }
    result = EC_KEY_set_private_key(ec_key, private_key_bn);
    if (!result) {
        return SUIT_FATAL_ERROR;
    }
    pub_key_point = EC_POINT_new(ec_group);
    if (pub_key_point == NULL) {
        return SUIT_FATAL_ERROR;
    }
    pub_key_point = EC_POINT_hex2point(ec_group, public_key, pub_key_point, NULL);
    if (pub_key_point == NULL) {
        return SUIT_FATAL_ERROR;
    }
    result = EC_KEY_set_public_key(ec_key, pub_key_point);
    if (result == 0) {
        return SUIT_FATAL_ERROR;
    }

    cose_key_pair->k.key_ptr  = ec_key;
    cose_key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;
}

int32_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    EC_GROUP    *ec_group = NULL;
    EC_KEY      *ec_key = NULL;
    EC_POINT    *ec_point = NULL;
    int         result = 0;

    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_group == NULL) {
        return SUIT_FAILED_TO_VERIFY;
    }
    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        return SUIT_FAILED_TO_VERIFY;
    }
    result = EC_KEY_set_group(ec_key, ec_group);
    if (!result) {
        return SUIT_FAILED_TO_VERIFY;
    }
    ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
        return SUIT_FAILED_TO_VERIFY;
    }
    ec_point = EC_POINT_hex2point(ec_group, public_key, ec_point, NULL);
    if (ec_point == NULL) {
        return SUIT_FAILED_TO_VERIFY;
    }
    result = EC_KEY_set_public_key(ec_key, ec_point);
    if (result == 0) {
        return SUIT_FAILED_TO_VERIFY;
    }

    cose_public_key->k.key_ptr  = ec_key;
    cose_public_key->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;
}
int32_t suit_sign_cose_sign1(const UsefulBufC *raw_cbor, const char *private_key, const char *public_key, UsefulBuf *returned_payload) {
    // Create cose signed file.
    struct t_cose_key cose_key_pair;
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;
    UsefulBufC tmp_signed_cose;
    UsefulBuf_MAKE_STACK_UB(signed_cose_buffer, 1024);

    int32_t result = suit_create_es256_key_pair(private_key, public_key, &cose_key_pair);
    if (result != SUIT_SUCCESS) {
        printf("Fail make_ossl_ecdsa_key_pair : result = %d\n", result);
        return result;
    }

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, cose_key_pair, NULL_Q_USEFUL_BUF_C);
    cose_result = t_cose_sign1_sign(&sign_ctx, *raw_cbor, signed_cose_buffer, &tmp_signed_cose);
    EC_KEY_free(cose_key_pair.k.key_ptr);

    if (cose_result != T_COSE_SUCCESS) {
        printf("Fail t_cose_sign1_sign : result = %d\n", cose_result);
        return SUIT_FATAL_ERROR;
    }
    memcpy(returned_payload->ptr, tmp_signed_cose.ptr, tmp_signed_cose.len);
    returned_payload->len = tmp_signed_cose.len;
    return SUIT_SUCCESS;
}

#endif /* LIBCSUIT_PSA_CRYPTO_C */

int32_t suit_verify_cose_sign1(const UsefulBufC *signed_cose, const char *public_key, UsefulBufC *returned_payload) {
    struct t_cose_key   cose_public_key;
    int32_t             result = SUIT_SUCCESS;
    if (public_key == NULL) {
        return SUIT_FAILED_TO_VERIFY;
    }

    result = suit_create_es256_public_key(public_key, &cose_public_key);
    if (result != SUIT_SUCCESS) {
        printf("Fail make_ossl_ecdsa_key_pair : result = %d\n", result);
        return SUIT_FAILED_TO_VERIFY;
    }

    struct t_cose_sign1_verify_ctx  verify_ctx;
    struct t_cose_parameters        parameters;
    enum t_cose_err_t               cose_result;
    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_public_key);
    cose_result = t_cose_sign1_verify(&verify_ctx,
                                      *signed_cose,
                                      returned_payload,
                                      &parameters);
     if (cose_result != SUIT_SUCCESS) {
         printf("Fail t_cose_sign1_verify : result = %d\n", cose_result);
         return SUIT_FAILED_TO_VERIFY;
     }
#if defined(LIBCSUIT_PSA_CRYPTO_C)
//  Destroy key 
#else
EC_KEY_free(cose_public_key.k.key_ptr);
#endif /* LIBCSUIT_PSA_CRYPTO_C */
     return SUIT_SUCCESS;
}