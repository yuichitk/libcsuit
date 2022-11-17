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
cose_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC signed_cose) {
    /* judge authentication object
     * [ COSE_Sign_Tagged, COSE_Sign1_Tagged, COSE_Mac_Tagged, COSE_Mac0_Tagged ]
     */
    cose_tag_key_t result = COSE_TAG_INVALID;
    uint8_t tag0 = ((uint8_t *)signed_cose.ptr)[0];
    uint8_t tag1;
    switch (tag0) {
    case 0xd1: // Tag(17)
        result = COSE_MAC0_TAGGED;
        break;
    case 0xd2: // Tag(18)
        result = COSE_SIGN1_TAGGED;
        break;
    case 0xe8:
        tag1 = ((uint8_t *)signed_cose.ptr)[1];
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

suit_err_t suit_verify_cose_mac0(const UsefulBufC signed_cose, const suit_key_t *secret_key, UsefulBufC returned_payload) {
    struct t_cose_mac_validate_ctx verify_ctx;
    struct t_cose_parameter parameter;
    struct t_cose_parameter *p_parameter = &parameter;
    enum t_cose_err_t cose_result;

    if (secret_key == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    t_cose_mac_validate_init(&verify_ctx, 0);
    t_cose_mac_set_validate_key(&verify_ctx, secret_key->cose_key);
    cose_result = t_cose_mac_validate_detached(&verify_ctx,
                                              signed_cose,
                                              &returned_payload,
                                              &p_parameter);
    if (cose_result != T_COSE_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_sign_cose_mac0(const UsefulBufC raw_cbor, const suit_key_t *secret_key, UsefulBuf *returned_payload) {
    struct t_cose_mac_calculate_ctx sign_ctx;
    enum t_cose_err_t cose_result;
    UsefulBufC tmp_signed_cose;

    t_cose_mac_compute_init(&sign_ctx, 0, secret_key->cose_algorithm_id);
    t_cose_mac_set_computing_key(&sign_ctx, secret_key->cose_key, NULL_Q_USEFUL_BUF_C);
    cose_result = t_cose_mac_compute_detached(&sign_ctx,
                                            NULL_Q_USEFUL_BUF_C,
                                            raw_cbor,
                                            *returned_payload,
                                            &tmp_signed_cose);
    if (cose_result != T_COSE_SUCCESS) {
        returned_payload->len = 0;
        return SUIT_ERR_FAILED_TO_SIGN;
    }
    returned_payload->len = tmp_signed_cose.len;
    return SUIT_SUCCESS;
}

suit_err_t suit_verify_cose_sign1(const UsefulBufC signed_cose, const suit_key_t *public_key, UsefulBufC returned_payload) {
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_parameters parameters;
    enum t_cose_err_t cose_result;

    if (public_key == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, public_key->cose_key);
    cose_result = t_cose_sign1_verify_detached(&verify_ctx,
                                               signed_cose,
                                               NULL_Q_USEFUL_BUF_C,
                                               returned_payload,
                                               &parameters);
    if (cose_result != T_COSE_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_sign_cose_sign1(const UsefulBufC raw_cbor, const suit_key_t *key_pair, UsefulBuf *returned_payload) {
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;
    UsefulBufC tmp_signed_cose;

    t_cose_sign1_sign_init(&sign_ctx, 0, key_pair->cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair->cose_key, NULL_Q_USEFUL_BUF_C);
    cose_result = t_cose_sign1_sign_detached(&sign_ctx,
                                             NULL_Q_USEFUL_BUF_C,
                                             raw_cbor,
                                             *returned_payload,
                                             &tmp_signed_cose);
    if (cose_result != T_COSE_SUCCESS) {
        returned_payload->len = 0;
        return SUIT_ERR_FAILED_TO_SIGN;
    }
    returned_payload->len = tmp_signed_cose.len;
    return SUIT_SUCCESS;
}

