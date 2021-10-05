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

    Call suit_process_envelopes() to process whole SUIT manifests at once.
    One or more manifests may depend other manifests.
 */

suit_err_t suit_in_component_index(QCBORDecodeContext *context,
                                   uint64_t *component_index) {
    // out of the current-list, by default
    suit_err_t result = SUIT_ERR_NO_MORE_ITEMS;
    QCBORItem item;
    union {
        int64_t int64;
        uint64_t uint64;
    } val;

    QCBORDecode_PeekNext(context, &item);
    switch (item.uDataType) {
    case QCBOR_TYPE_INT64:
        QCBORDecode_GetInt64(context, &val.int64);
        if (val.int64 < 0) {
            result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        }
        else {
            *component_index = (uint64_t)val.int64;
            result = SUIT_SUCCESS;
        }
        break;
    case QCBOR_TYPE_UINT64:
        QCBORDecode_GetUInt64(context, component_index);
        result = SUIT_SUCCESS;
        break;
    case QCBOR_TYPE_ARRAY:
        result = SUIT_ERR_NOT_IMPLEMENTED;
        break;
    case QCBOR_TYPE_TRUE:
        result = SUIT_ERR_NOT_IMPLEMENTED;
        break;
    case QCBOR_TYPE_FALSE:
        QCBORDecode_GetNext(context, &item);
        break;
    default:
        result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
    }
    return result;
}

suit_err_t suit_set_parameters(QCBORDecodeContext *context,
                               bool to_override,
                               suit_parameter_args_t *parameters) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORItem item;
    QCBORDecode_EnterMap(context, &item);

    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
        result = suit_qcbor_get_next(context, &item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        int64_t label = item.label.int64;

        switch (label) {
        case SUIT_PARAMETER_URI:
            if (item.uDataType != QCBOR_TYPE_TEXT_STRING) {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                goto out;
            }
            if (!(parameters->exists & SUIT_PARAMETER_CONTAINS_URI) || to_override) {
                parameters->uri_list[0] = item.val.string;
                parameters->uri_list_len = 1;
            }
            break;
        default:
            QCBORDecode_GetNext(context, &item);
        }
    }

    QCBORDecode_ExitMap(context);
out:
    return result;
}

/*
            QCBORDecode_EnterArray(&context, &item);
            params_len = item.val.uCount;
            for (size_t j = 0; j < params_len; j++) {
                //NOTE: common-sequence is like [ labelA, valueA, labelB, valueB, ... ]
                int64_t params_label;
                QCBORDecode_GetInt64(&context, &params_label);
                switch (params_label) {
            }


*/

suit_err_t suit_process_command(const uint8_t command,
                                UsefulBufC buf,
                                suit_common_args_t *suit_common_args,
                                const suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    union {
        suit_fetch_args_t fetch;
    } args;
    bool to_override = false;
    suit_parameter_args_t tmp_parameters;
    uint64_t component_index = 0;
    if (command != SUIT_COMMON) {
        memcpy(&tmp_parameters, &suit_common_args->parameters, sizeof(suit_parameter_args_t));
    }

    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&context, buf, QCBOR_DECODE_MODE_NORMAL);
    int64_t condition_directive_key = SUIT_CONDITION_INVALID;

    QCBORDecode_EnterArray(&context, &item);
    const size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i += 2) {
        report_t reporting_policy;
        QCBORDecode_GetInt64(&context, &condition_directive_key);

        switch (condition_directive_key) {
        case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            result = suit_in_component_index(&context, &component_index);
            break;

        case SUIT_CONDITION_VENDOR_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_CLASS_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_IMAGE_MATCH:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_USE_BEFORE:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_COMPONENT_SLOT:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_ABORT:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_DEVICE_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_IMAGE_NOT_MATCH:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_MINIMUM_BATTERY:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_UPDATE_AUTHORIZED:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;
        case SUIT_CONDITION_VERSION:
            QCBORDecode_GetUInt64(&context, &reporting_policy.val);
            break;

        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            to_override = true;
        case SUIT_DIRECTIVE_SET_PARAMETERS:
            suit_set_parameters(&context, to_override, &suit_common_args->parameters);
            to_override = false;
            break;
        case SUIT_DIRECTIVE_FETCH:
            if (suit_callbacks->fetch != NULL && suit_common_args->parameters.uri_list_len > 0) {
                if (suit_common_args->parameters.uri_list[0].len >= SUIT_MAX_NAME_LENGTH) {
                    result = SUIT_ERR_NO_MEMORY;
                }
                else {
                    args.fetch = (suit_fetch_args_t){0};
                    memcpy(args.fetch.uri, suit_common_args->parameters.uri_list[0].ptr, suit_common_args->parameters.uri_list[0].len);
                    args.fetch.uri[suit_common_args->parameters.uri_list[0].len] = '\0';
                    args.fetch.uri_len = suit_common_args->parameters.uri_list[0].len;
                    result = suit_callbacks->fetch(args.fetch);
                }
            }
            break;
        case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
        case SUIT_DIRECTIVE_TRY_EACH:
        case SUIT_DIRECTIVE_DO_EACH:
        case SUIT_DIRECTIVE_MAP_FILTER:
        case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
        case SUIT_DIRECTIVE_COPY:
        case SUIT_DIRECTIVE_RUN:
        case SUIT_DIRECTIVE_WAIT:
        case SUIT_DIRECTIVE_FETCH_URI_LIST:
        case SUIT_DIRECTIVE_SWAP:
        case SUIT_DIRECTIVE_RUN_SEQUENCE:

        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
        }
        error = QCBORDecode_GetError(&context);
        if (result != SUIT_SUCCESS) {
            goto error;
        }
    }
    QCBORDecode_ExitArray(&context);
    error = QCBORDecode_Finish(&context);

    if (result != SUIT_SUCCESS || error != QCBOR_SUCCESS) {
        goto error;
    }

    switch (command) {
    case SUIT_INSTALL:
        break;
    case SUIT_VALIDATE:
        break;
    }
    return result;

error:
    if (suit_callbacks->on_error != NULL || result != SUIT_ERR_ABORT) {
        suit_callbacks->on_error(
            (suit_on_error_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = command,
                .level2.condition_directive = condition_directive_key,
                .level3.parameter = SUIT_PARAMETER_INVALID,
                .qcbor_error = error,
                .suit_error = result
            }
        );
        return SUIT_ERR_ABORT;
    }
    return result;
}

suit_err_t suit_process_common_sequence(QCBORDecodeContext *context,
                                           const uint8_t command,
                                           suit_common_args_t *suit_common_args,
                                           const suit_inputs_t *suit_inputs,
                                           const suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    UsefulBufC buf;
    QCBORDecode_GetByteString(context, &buf);

    result = suit_process_command(command, buf, suit_common_args, suit_callbacks);
    return result;
}

suit_err_t suit_process_validate(QCBORDecodeContext *context,
                                 suit_common_args_t *suit_common_args,
                                 const suit_inputs_t *suit_inputs,
                                 const suit_callbacks_t *suit_callbacks) {
    return suit_process_common_sequence(context, SUIT_VALIDATE, suit_common_args, suit_inputs, suit_callbacks);
}

suit_err_t suit_process_install(QCBORDecodeContext *context,
                                suit_common_args_t *suit_common_args,
                                const suit_inputs_t *suit_inputs,
                                const suit_callbacks_t *suit_callbacks) {
    return suit_process_common_sequence(context, SUIT_INSTALL, suit_common_args, suit_inputs, suit_callbacks);
}

/*
    component_index
        Negative: All
        0 or Positive: Only the target component
 */
suit_err_t suit_process_common(UsefulBufC common,
                               const int64_t component_index,
                               const suit_manifest_key_t action,
                               suit_callbacks_t *suit_callbacks,
                               suit_common_args_t *suit_common_args) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORError error;
    QCBORItem item;

    UsefulBufC buf;
    suit_components_t components;
    size_t params_len;

    QCBORDecode_Init(&context, common, QCBOR_DECODE_MODE_NORMAL);
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
        case SUIT_COMMON_SEQUENCE:
            QCBORDecode_GetByteString(&context, &buf);
            suit_process_command(SUIT_COMMON, buf, suit_common_args, suit_callbacks);
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

suit_err_t suit_process_manifest(QCBORDecodeContext *context,
                                 suit_digest_t *digest,
                                 suit_common_args_t *suit_common_args,
                                 suit_inputs_t *suit_inputs,
                                 suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORError error;
    QCBORItem item;
    UsefulBufC suit_common_buf;
    suit_common_buf.len = 0;
    union {
        int64_t int64;
        uint64_t uint64;
        UsefulBufC string;
    } val;

    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(context, &item);
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
            QCBORDecode_GetByteString(context, &suit_common_buf);
            result = suit_process_common(suit_common_buf, -1, 0, suit_callbacks, suit_common_args);
            break;
        case SUIT_MANIFEST_SEQUENCE_NUMBER:
            QCBORDecode_GetUInt64(context, &suit_common_args->manifest_sequence_number);
            break;
        case SUIT_INSTALL:
            result = suit_process_install(context, suit_common_args, suit_inputs, suit_callbacks);
            break;
        case SUIT_VALIDATE:
            result = suit_process_validate(context, suit_common_args, suit_inputs, suit_callbacks);
            break;
        case SUIT_RUN:
            /* TODO */
            QCBORDecode_GetNext(context, &item);
            break;
        case SUIT_REFERENCE_URI:
        case SUIT_DEPENDENCY_RESOLUTION:
        case SUIT_PAYLOAD_FETCH:
        case SUIT_LOAD:
        case SUIT_TEXT:
        case SUIT_COSWID:
        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            goto out;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    QCBORDecode_ExitMap(context);
    QCBORDecode_ExitBstrWrapped(context);
out:
    if (error != QCBOR_SUCCESS || result != SUIT_SUCCESS) {
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

suit_err_t suit_process_authentication_wrapper(QCBORDecodeContext *context,
                                               suit_inputs_t *suit_inputs,
                                               suit_digest_t *digest) {
    QCBORItem item;

    /* authentication-wrapper */
    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterArray(context, &item);
    size_t length = item.val.uCount;
    if (length < 1) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

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

    return SUIT_SUCCESS;
}

/*
    Public function. See suit_manifest_process.h
 */
suit_err_t suit_process_envelopes(suit_inputs_t *suit_inputs, suit_callbacks_t *suit_callbacks) {
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
                break;
            case SUIT_AUTHENTICATION:
                result = suit_process_authentication_wrapper(&context, suit_inputs, &digests[i]);
                break;
            case SUIT_MANIFEST:
                if (digests[i].algorithm_id == SUIT_ALGORITHM_ID_INVALID) {
                    result = SUIT_ERR_AUTHENTICATION_POSITION;
                }
                else {
                    QCBORDecode_GetNext(&context, &item);
                    result = suit_verify_item(&context, &item, &digests[i]);
                }
                break;
            case SUIT_DELEGATION:
                // fall through

            /* Severed Members */
            case SUIT_INSTALL:
            case SUIT_DEPENDENCY_RESOLUTION:
            case SUIT_PAYLOAD_FETCH:
            case SUIT_TEXT:
            case SUIT_COSWID:
                QCBORDecode_GetByteString(&context, &val.string);
                /* TODO: have to check the digest */
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
        suit_common_args_t suit_common_args = {0};

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
            case SUIT_MANIFEST:
                result = suit_process_manifest(&context, &digests[i], &suit_common_args, suit_inputs, suit_callbacks);
                break;
            case SUIT_DELEGATION:
                /* TODO */
            case SUIT_AUTHENTICATION:
                /* Skip */
                QCBORDecode_GetByteString(&context, &val.string);
                break;

            /* Severed Members */
            case SUIT_INSTALL:
                //TODO: suit_verify_digest(context, suit_common_args.signatures.install);
                suit_process_install(&context, &suit_common_args, suit_inputs, suit_callbacks);
                break;
            case SUIT_DEPENDENCY_RESOLUTION:
            case SUIT_PAYLOAD_FETCH:
            case SUIT_TEXT:
            case SUIT_COSWID:
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

out:
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}
