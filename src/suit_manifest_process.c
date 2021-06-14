/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_manifest_process.h"
#include "suit_cose.h"
#include "suit_digest.h"
#include <inttypes.h>

/*!
    \file   suit_manifest_process.c

    \brief  This implements libcsuit processing

    Call suit_process_envelope() to process whole SUIT manifest.
 */

/*
    component_index
        Negative: All
        0 or Positive: Only the target component
 */
suit_err_t suit_process_common(const suit_buf_t *common, const int64_t component_index, const suit_manifest_key_t action, suit_process_t *suit_process) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORError error;
    QCBORItem item;

    suit_components_t components;
    union {
        suit_install_t install;
    } action_params;

    QCBORDecode_Init(&context, (UsefulBufC){common->ptr, common->len}, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(&context, &item);
    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
        error = QCBORDecode_GetNext(&context, &item);
        if (error != QCBOR_SUCCESS) {
            goto out;
        }
        int64_t label = item.label.int64;
        switch (label) {
        case SUIT_COMPONENTS:
            QCBORDecode_EnterArray(&context, &item);
            components.len = item.val.uCount;
            for (size_t j = 0; j < components.len; j++) {
                UsefulBufC  identifier;
                QCBORDecode_EnterArray(&context, &item);
                components.comp_id[j].len = item.val.uCount;
                for (size_t k = 0; j < components.comp_id[j].len; k++) {
                    QCBORDecode_GetByteString(&context, &identifier);
                    components.comp_id[j].identifier[k].ptr = identifier.ptr;
                    components.comp_id[j].identifier[k].len = identifier.len;
                }
                QCBORDecode_ExitArray(&context);
            }
            QCBORDecode_ExitArray(&context);
            break;
        }
    }
    QCBORDecode_ExitMap(&context);
    QCBORDecode_ExitBstrWrapped(&context);

    error = QCBORDecode_Finish(&context);
out:
    if (result != SUIT_SUCCESS && error != QCBOR_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_process_manifest(QCBORDecodeContext *context, suit_digest_t *digest, suit_process_t *suit_process) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORError error;
    QCBORItem item;
    suit_buf_t  suit_common_buf;
    suit_common_buf.len = 0;
    suit_common_params_t suit_common;

    union {
        int64_t int64;
        uint64_t uint64;
        UsefulBufC string;
    } val;

    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    result = suit_qcbor_get_next(context, &item, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        goto out;
    }
    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
        error = QCBORDecode_PeekNext(context, &item);
        if (error != QCBOR_SUCCESS) {
            goto out;
        }
        int64_t label = item.label.int64;
        switch (label) {
        case SUIT_MANIFEST_VERSION:
            QCBORDecode_GetInt64(context, &val.int64);
            if (val.int64 != 1) {
                result = SUIT_ERR_NOT_IMPLEMENTED;
                goto out;
            }
            break;
        case SUIT_COMMON:
            QCBORDecode_GetByteString(context, &val.string);
            suit_common_buf.ptr = val.string.ptr;
            suit_common_buf.len = val.string.len;
            suit_process_common(&suit_common_buf, -1, 0, suit_process);
            break;
        case SUIT_MANIFEST_SEQUENCE_NUMBER:
        case SUIT_REFERENCE_URI:
        case SUIT_DEPENDENCY_RESOLUTION:
        case SUIT_PAYLOAD_FETCH:
        case SUIT_INSTALL:
        case SUIT_VALIDATE:
        case SUIT_LOAD:
        case SUIT_RUN:
        case SUIT_TEXT:
        case SUIT_COSWID:
        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            goto out;
        }
        if (result != SUIT_SUCCESS) {
            goto out;
        }
    }

    QCBORDecode_ExitBstrWrapped(context);
out:
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

void suit_process_digest(QCBORDecodeContext *context, suit_digest_t *digest) {
    int64_t algorithm_id;
    UsefulBufC digest_bytes;
    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterArray(context, NULL);
    QCBORDecode_GetInt64(context, &algorithm_id);
    QCBORDecode_GetByteString(context, &digest_bytes);
    digest->algorithm_id = algorithm_id;
    digest->bytes.ptr = digest_bytes.ptr;
    digest->bytes.len = digest_bytes.len;
    QCBORDecode_ExitArray(context);
    QCBORDecode_ExitBstrWrapped(context);
}

suit_err_t suit_process_authentication_wrapper(QCBORDecodeContext *context, suit_inputs_t *suit_inputs, suit_digest_t *digest) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORError error = QCBOR_SUCCESS;
    QCBORItem item;

    /* authentication-wrapper */
    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterArray(context, &item);
    size_t length = item.val.uCount;

    /* digest */
    suit_process_digest(context, digest);

    /* signatures */
    UsefulBufC signature;
    for (size_t i = 1; i < length; i++) {
        QCBORDecode_GetByteString(context, &signature);
        /* TODO: ignore signature for now */
    }
    QCBORDecode_ExitArray(context);
    QCBORDecode_ExitBstrWrapped(context);

out:
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

/*
    Public function. See suit_manifest_process.h
 */
suit_err_t suit_process_envelopes(suit_process_t *suit_process) {
    suit_inputs_t *suit_inputs = &suit_process->suit_inputs;
    suit_digest_t digests[SUIT_MAX_ARRAY_LENGTH];
    QCBORDecodeContext context;
    QCBORError error;
    QCBORItem item;
    suit_err_t result = SUIT_SUCCESS;
    union {
        int64_t int64;
        uint64_t uint64;
        UsefulBufC string;
    } val;

    if (suit_inputs->manifest_len > SUIT_MAX_ARRAY_LENGTH) {
        return SUIT_ERR_NO_MEMORY;
    }

    /* first, fetch & check the digest from each manifest */
    for (size_t i = 0; i < suit_inputs->manifest_len; i++) {
        QCBORDecode_Init(&context,
                         (UsefulBufC){suit_inputs->manifests[i].ptr, suit_inputs->manifests[i].len},
                         QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterMap(&context, &item);
        size_t length = item.val.uCount;
        for (size_t j = 0; j < length; j++) {
            error = QCBORDecode_PeekNext(&context, &item);
            if (error != QCBOR_SUCCESS) {
                goto out;
            }
            int64_t label = item.label.int64;
            switch (label) {
            case SUIT_AUTHENTICATION:
                suit_process_authentication_wrapper(&context, suit_inputs, &digests[i]);
                break;
            case SUIT_MANIFEST:
                if (digests[i].algorithm_id == SUIT_ALGORITHM_ID_INVALID) {
                    result = SUIT_ERR_AUTHENTICATION_POSITION;
                }
                else {
                    QCBORDecode_GetNext(&context, &item);
                    result = suit_verify_item(&context, &item, &digests[i], true);
                }
                break;
            case SUIT_DELEGATION:
                QCBORDecode_GetByteString(&context, &val.string);
                break;
            default:
                result = SUIT_ERR_NOT_IMPLEMENTED;
                break;
            }
            if (result != SUIT_SUCCESS) {
                goto out;
            }
        }
        QCBORDecode_ExitMap(&context);
        error = QCBORDecode_Finish(&context);
        if (error != QCBOR_SUCCESS) {
            goto out;
        }
    }

    /* second, parse & process fetch & check the digest from each manifest */
    for (size_t i = 0; i < suit_inputs->manifest_len; i++) {
        QCBORDecode_Init(&context,
                         (UsefulBufC){suit_inputs->manifests[i].ptr, suit_inputs->manifests[i].len},
                         QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterMap(&context, &item);
        size_t length = item.val.uCount;
        for (size_t j = 0; j < length; j++) {
            result = suit_qcbor_peek_next(&context, &item, QCBOR_TYPE_ANY);
            if (result != SUIT_SUCCESS) {
                goto out;
            }
            int64_t label = item.label.int64;
            switch (label) {
            case SUIT_MANIFEST:
                result = suit_process_manifest(&context, &digests[i], suit_process);
                break;
            case SUIT_DELEGATION:
                /* TODO */
            case SUIT_AUTHENTICATION:
                /* Skip */
                QCBORDecode_GetByteString(&context, &val.string);
                break;
            }
            if (result != SUIT_SUCCESS) {
                goto out;
            }
        }
        QCBORDecode_ExitMap(&context);
        error = QCBORDecode_Finish(&context);
        if (error != QCBOR_SUCCESS) {
            goto out;
        }
    }

out:
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}
