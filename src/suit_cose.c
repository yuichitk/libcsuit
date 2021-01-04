/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#include "suit_cose.h"
#include "suit_common.h"

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

     EC_KEY_free(cose_public_key.k.key_ptr);
     return SUIT_SUCCESS;
}
