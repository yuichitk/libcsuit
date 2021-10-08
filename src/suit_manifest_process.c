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
#if 0
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
#endif

suit_err_t suit_set_parameters(QCBORDecodeContext *context,
                               const suit_rep_policy_key_t directive,
                               suit_parameter_args_t *parameters,
                               const suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    QCBORDecode_EnterMap(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        goto error;
    }
    suit_parameter_key_t parameter;

    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
        QCBORDecode_PeekNext(context, &item);
        if (!(item.uLabelType == QCBOR_TYPE_INT64 || item.uLabelType == QCBOR_TYPE_UINT64)) {
            result = SUIT_ERR_INVALID_TYPE_OF_KEY;
            goto error;
        }
        parameter = item.label.int64;

        switch (parameter) {
        case SUIT_PARAMETER_URI:
            if (!(parameters->exists & SUIT_PARAMETER_CONTAINS_URI) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                QCBORDecode_GetTextString(context, &parameters->uri_list[0]);
                parameters->uri_list_len = 1;
            }
            break;
        case SUIT_PARAMETER_IMAGE_DIGEST:
            QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
            result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, context, &item, true, &parameters->image_digest);
            QCBORDecode_ExitBstrWrapped(context);
            break;
        case SUIT_PARAMETER_IMAGE_SIZE:
            result = suit_qcbor_get_next_uint(context, &item);
            if (result == SUIT_SUCCESS) {
                parameters->image_size = item.val.uint64;
            }
            break;
        case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            QCBORDecode_GetByteString(context, &parameters->vendor_id);
            break;
        case SUIT_PARAMETER_CLASS_IDENTIFIER:
            QCBORDecode_GetByteString(context, &parameters->class_id);
            break;
        default:
            QCBORDecode_GetNext(context, &item);
        }
        if (result != SUIT_SUCCESS) {
            goto error;
        }
        error = QCBORDecode_GetError(context);
        if (error != QCBOR_SUCCESS) {
            goto error;
        }
    }

    QCBORDecode_ExitMap(context);
    return result;

error:
    if (suit_callbacks->on_error != NULL || result != SUIT_ERR_ABORT) {
        suit_callbacks->on_error(
            (suit_on_error_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = SUIT_COMMON,
                .level2.common_key = SUIT_COMMON_SEQUENCE,
                .level3.condition_directive = directive,
                .level4.parameter = parameter,
                .qcbor_error = error,
                .suit_error = result
            }
        );
        return SUIT_ERR_ABORT;
    }
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

suit_err_t suit_process_common_sequence(const suit_extracted_t *extracted,
                                        suit_parameter_args_t common_parameters[],
                                        const suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    suit_rep_policy_key_t condition_directive_key;
    size_t component_index = 0;
    suit_report_t report;

    QCBORDecode_Init(&context, extracted->common_sequence, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterArray(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY) {
        result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        goto error;
    }
    size_t length = item.val.uCount;
    if (length % 2 != 0) {
        result = SUIT_ERR_NO_MORE_ITEMS;
        goto error;
    }
    for (size_t i = 0; i < length; i += 2) {
        result = suit_qcbor_get_next_uint(&context, &item);
        if (result != SUIT_SUCCESS) {
            goto error;
        }
        condition_directive_key = item.val.uint64;
        switch (condition_directive_key) {
        case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            result = suit_qcbor_get_next_uint(&context, &item);
            if (result != SUIT_SUCCESS) {
                goto error;
            }
            component_index = item.val.uint64;
            if (component_index >= SUIT_MAX_COMPONENT_NUM) {
                result = SUIT_ERR_NO_MEMORY;
                goto error;
            }
            break;
        case SUIT_DIRECTIVE_SET_PARAMETERS:
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_SET_PARAMETERS, &common_parameters[component_index], suit_callbacks);
            break;
        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, &common_parameters[component_index], suit_callbacks);
            break;
        case SUIT_CONDITION_VENDOR_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_CLASS_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_IMAGE_MATCH:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_USE_BEFORE:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_COMPONENT_SLOT:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_ABORT:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_DEVICE_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_IMAGE_NOT_MATCH:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_MINIMUM_BATTERY:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_UPDATE_AUTHORIZED:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_VERSION:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;

        case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
        case SUIT_DIRECTIVE_RUN_SEQUENCE:
        case SUIT_DIRECTIVE_TRY_EACH:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            break;
        default:
            result = SUIT_ERR_INVALID_TYPE_OF_KEY;
        }
        if (result != SUIT_SUCCESS) {
            goto error;
        }
    }


    QCBORDecode_ExitArray(&context);
    error = QCBORDecode_Finish(&context);
    if (error != QCBOR_SUCCESS) {
        goto error;
    }
    return result;

error:
    if (suit_callbacks->on_error != NULL || result != SUIT_ERR_ABORT) {
        suit_callbacks->on_error(
            (suit_on_error_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = SUIT_COMMON,
                .level2.common_key = SUIT_COMMON_SEQUENCE,
                .level3.condition_directive = condition_directive_key,
                .level4.parameter = SUIT_PARAMETER_INVALID,
                .qcbor_error = error,
                .suit_error = result
            }
        );
        return SUIT_ERR_ABORT;
    }
    return result;

}

suit_err_t suit_process_command_sequence(const suit_manifest_key_t command,
                                         const suit_inputs_t *suit_inputs,
                                         const suit_extracted_t *extracted,
                                         const suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    UsefulBufC buf;
    union {
        suit_fetch_args_t fetch;
        suit_run_args_t run;
    } args;
    size_t component_index = 0;
    suit_parameter_args_t common_parameters[SUIT_MAX_COMPONENT_NUM];

    suit_rep_policy_key_t condition_directive_key = SUIT_CONDITION_INVALID;
    suit_report_t report;

    switch (command) {
    case SUIT_DEPENDENCY_RESOLUTION:
        buf = extracted->dependency_resolution;
        break;
    case SUIT_PAYLOAD_FETCH:
        buf = extracted->payload_fetch;
        break;
    case SUIT_INSTALL:
        buf = extracted->install;
        break;
    case SUIT_VALIDATE:
        buf = extracted->validate;
        break;
    case SUIT_LOAD:
        buf = extracted->load;
        break;
    case SUIT_RUN:
        buf = extracted->run;
        break;
    default:
        result = SUIT_ERR_INVALID_KEY;
        goto error;
    }
    if (buf.len == 0 || buf.ptr == NULL) {
        return SUIT_SUCCESS;
    }

    memset(common_parameters, 0, sizeof(common_parameters));
    result = suit_process_common_sequence(extracted, common_parameters, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    QCBORDecode_Init(&context, buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&context, &item);
    const size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i += 2) {
        result = suit_qcbor_get_next_uint(&context, &item);
        if (result != SUIT_SUCCESS) {
            goto error;
        }
        condition_directive_key = item.val.uint64;

        switch (condition_directive_key) {
        case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            result = suit_qcbor_get_next_uint(&context, &item);
            if (result != SUIT_SUCCESS) {
                goto error;
            }
            QCBORDecode_GetUInt64(&context, &component_index);
            break;

        case SUIT_CONDITION_VENDOR_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_CLASS_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_IMAGE_MATCH:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_USE_BEFORE:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_COMPONENT_SLOT:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_ABORT:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_DEVICE_IDENTIFIER:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_IMAGE_NOT_MATCH:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_MINIMUM_BATTERY:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_UPDATE_AUTHORIZED:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;
        case SUIT_CONDITION_VERSION:
            QCBORDecode_GetUInt64(&context, &report.val);
            // TODO: check condition
            break;

        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, common_parameters, suit_callbacks);
            break;
        case SUIT_DIRECTIVE_SET_PARAMETERS:
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_SET_PARAMETERS, common_parameters, suit_callbacks);
            break;
        case SUIT_DIRECTIVE_FETCH:
            if (suit_callbacks->fetch == NULL) {
                result = SUIT_ERR_NO_CALLBACK;
                goto error;
            }
            if (common_parameters[component_index].uri_list_len == 0) {
                result = SUIT_ERR_NO_ARGUMENT;
                goto error;
            }
            if (common_parameters[component_index].uri_list[0].len >= SUIT_MAX_NAME_LENGTH) {
                result = SUIT_ERR_NO_MEMORY;
                goto error;
            }
            args.fetch = (suit_fetch_args_t){0};
            QCBORDecode_GetUInt64(&context, &args.fetch.report.val);
            memcpy(args.fetch.uri, common_parameters[component_index].uri_list[0].ptr, common_parameters[component_index].uri_list[0].len);
            args.fetch.uri[common_parameters[component_index].uri_list[0].len] = '\0';
            args.fetch.uri_len = common_parameters[component_index].uri_list[0].len;
            result = suit_callbacks->fetch(args.fetch);
            break;
        case SUIT_DIRECTIVE_RUN:
            if (suit_callbacks->run == NULL) {
                result = SUIT_ERR_NO_CALLBACK;
                goto error;
            }
            else if (extracted->components.len < component_index || extracted->components.comp_id[component_index].len == 0) {
                result = SUIT_ERR_NO_ARGUMENT;
                goto error;
            }
            args.run = (suit_run_args_t){0};
            QCBORDecode_GetUInt64(&context, &args.run.report.val);

            args.run.component_identifier = extracted->components.comp_id[component_index];
            args.run.args_len = common_parameters[component_index].run_args.len;
            if (args.run.args_len > 0) {
                memcpy(args.run.args, common_parameters[component_index].run_args.ptr, args.run.args_len);
            }
            result = suit_callbacks->run(args.run);
            break;
        case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
        case SUIT_DIRECTIVE_TRY_EACH:
        case SUIT_DIRECTIVE_DO_EACH:
        case SUIT_DIRECTIVE_MAP_FILTER:
        case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
        case SUIT_DIRECTIVE_COPY:
        case SUIT_DIRECTIVE_WAIT:
        case SUIT_DIRECTIVE_FETCH_URI_LIST:
        case SUIT_DIRECTIVE_SWAP:
        case SUIT_DIRECTIVE_RUN_SEQUENCE:

        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (result != SUIT_SUCCESS) {
            goto error;
        }
        error = QCBORDecode_GetError(&context);
        if (error != QCBOR_SUCCESS) {
            goto error;
        }
    }
    QCBORDecode_ExitArray(&context);
    error = QCBORDecode_Finish(&context);
    if (error != QCBOR_SUCCESS) {
        goto error;
    }

    switch (command) {
    case SUIT_INSTALL:
        break;
    case SUIT_VALIDATE:
        break;
    default:
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
                .suit_error = result,
                .report = report
            }
        );
        return SUIT_ERR_ABORT;
    }
    return result;
}

/*
suit_err_t suit_process_validate(QCBORDecodeContext *context,
                                 suit_common_args_t *suit_common_args,
                                 const suit_inputs_t *suit_inputs,
                                 const suit_callbacks_t *suit_callbacks) {
    return suit_process_common_sequence(context, SUIT_VALIDATE, suit_common_args, suit_inputs, suit_callbacks);
}
*/

suit_err_t suit_process_install(const suit_inputs_t *suit_inputs,
                                const suit_extracted_t *extracted,
                                const suit_callbacks_t *suit_callbacks) {
    return suit_process_command_sequence(SUIT_INSTALL, suit_inputs, extracted, suit_callbacks);
}

/*
    component_index
        Negative: All
        0 or Positive: Only the target component
 */
#if 0
suit_err_t suit_process_common(UsefulBufC common,
                               const int64_t component_index,
                               const suit_manifest_key_t action,
                               suit_callbacks_t *suit_callbacks,
                               suit_common_args_t *suit_common_args) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORError error = QCBOR_SUCCESS;
    QCBORItem item;

    UsefulBufC buf;
    suit_components_t components;

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
#endif

#if 0
suit_err_t suit_process_manifest(QCBORDecodeContext *context,
                                 suit_digest_t *digest,
                                 suit_common_args_t *suit_common_args,
                                 suit_inputs_t *suit_inputs,
                                 suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORError error = QCBOR_SUCCESS;
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
#endif

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

suit_err_t suit_extract_common(QCBORDecodeContext *context,
                               suit_extracted_t *extracted,
                               const suit_callbacks_t *suit_callbacks) {
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    suit_err_t result = SUIT_SUCCESS;
    suit_manifest_key_t manifest_key = SUIT_COMMON;
    suit_common_key_t common_key = SUIT_COMMON_KEY_INVALID;

    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        goto error;
    }
    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
        error = QCBORDecode_PeekNext(context, &item);
        if (error != QCBOR_SUCCESS) {
            goto error;
        }
        else if (!(item.uLabelType == QCBOR_TYPE_INT64 || item.uLabelType == QCBOR_TYPE_UINT64)) {
            result = SUIT_ERR_INVALID_TYPE_OF_KEY;
        }
        common_key = item.label.int64;
        switch (common_key) {
        case SUIT_DEPENDENCIES:
            result = suit_decode_dependencies_from_item(SUIT_DECODE_MODE_STRICT, context, &item, true, &extracted->dependencies);
            break;
        case SUIT_COMPONENTS:
            result = suit_decode_components_from_item(SUIT_DECODE_MODE_STRICT, context, &item, true, &extracted->components);
            break;
        case SUIT_COMMON_SEQUENCE:
            QCBORDecode_GetByteString(context, &extracted->common_sequence);
            break;
        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (result != SUIT_SUCCESS) {
            goto error;
        }
    }
    QCBORDecode_ExitMap(context);
    QCBORDecode_ExitBstrWrapped(context);

    return result;

error:
    if (suit_callbacks->on_error != NULL || result != SUIT_ERR_ABORT) {
        suit_callbacks->on_error(
            (suit_on_error_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = manifest_key,
                .level2.common_key = common_key,
                .level3.parameter = SUIT_PARAMETER_INVALID,
                .qcbor_error = error,
                .suit_error = result
            }
        );
        return SUIT_ERR_ABORT;
    }
    return result;
}


suit_err_t suit_extract_manifest(UsefulBufC manifest,
                                 suit_extracted_t *extracted,
                                 const suit_callbacks_t *suit_callbacks) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;

    suit_manifest_key_t manifest_key;

    QCBORDecode_Init(&context, manifest, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        goto error;
    }
    size_t manifest_key_len = item.val.uCount;
    for (size_t j = 0; j < manifest_key_len; j++) {
        error = QCBORDecode_PeekNext(&context, &item);
        if (error != QCBOR_SUCCESS) {
            goto error;
        }
        if (!(item.uLabelType == QCBOR_TYPE_INT64 || item.uLabelType == QCBOR_TYPE_UINT64)) {
            result = SUIT_ERR_INVALID_TYPE_OF_KEY;
            goto error;
        }
        manifest_key = item.label.int64;
        switch (manifest_key) {
        case SUIT_MANIFEST_VERSION:
            error = QCBORDecode_GetNext(&context, &item);
            if (error != QCBOR_SUCCESS) {
                goto error;
            }
            if (!(item.uDataType == QCBOR_TYPE_INT64 || item.uDataType == QCBOR_TYPE_UINT64)) {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                goto error;
            }
            if (item.val.int64 != 1) {
                result = SUIT_ERR_INVALID_MANIFEST_VERSION;
            }
            break;
        case SUIT_MANIFEST_SEQUENCE_NUMBER:
            error = QCBORDecode_GetNext(&context, &item);
            if (error != QCBOR_SUCCESS) {
                goto error;
            }
            if (!(item.uDataType == QCBOR_TYPE_INT64 || item.uDataType == QCBOR_TYPE_UINT64)) {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                goto error;
            }
            // TODO: check sequence-number
            break;
        case SUIT_COMMON:
            result = suit_extract_common(&context, extracted, suit_callbacks);
            if (result != SUIT_SUCCESS) {
                goto error;
            }
            break;
        case SUIT_REFERENCE_URI:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            break;
        case SUIT_VALIDATE:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->validate);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;
        case SUIT_DEPENDENCY_RESOLUTION:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->dependency_resolution);
            }
            else if (item.uDataType == QCBOR_TYPE_ARRAY) {
                result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, &context, &item, true, &extracted->dependency_resolution_digest);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;

        case SUIT_PAYLOAD_FETCH:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->payload_fetch);
            }
            else if (item.uDataType == QCBOR_TYPE_ARRAY) {
                result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, &context, &item, true, &extracted->payload_fetch_digest);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;
        case SUIT_INSTALL:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->install);
            }
            else if (item.uDataType == QCBOR_TYPE_ARRAY) {
                result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, &context, &item, true, &extracted->install_digest);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;
        case SUIT_LOAD:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->load);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;
        case SUIT_RUN:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->run);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;
        case SUIT_TEXT:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->text);
            }
            else if (item.uDataType == QCBOR_TYPE_ARRAY) {
                result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, &context, &item, true, &extracted->text_digest);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;
        case SUIT_COSWID:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->coswid);
            }
            else if (item.uDataType == QCBOR_TYPE_ARRAY) {
                result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, &context, &item, true, &extracted->coswid_digest);
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            break;

        default:
            result = SUIT_ERR_INVALID_KEY;
            goto error;
        }

    }

    return result;

error:
    if (suit_callbacks->on_error != NULL || result != SUIT_ERR_ABORT) {
        suit_callbacks->on_error(
            (suit_on_error_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = manifest_key,
                .level2.condition_directive = SUIT_CONDITION_INVALID,
                .level3.parameter = SUIT_PARAMETER_INVALID,
                .qcbor_error = error,
                .suit_error = result
            }
        );
        return SUIT_ERR_ABORT;
    }
    return result;

}

/*
    Public function. See suit_manifest_process.h
 */
suit_err_t suit_process_envelopes(suit_inputs_t *suit_inputs, suit_callbacks_t *suit_callbacks) {
    QCBORDecodeContext context;
    QCBORError error = QCBOR_SUCCESS;
    QCBORItem item;
    suit_err_t result = SUIT_SUCCESS;
    /*
    union {
        int64_t int64;
        uint64_t uint64;
        UsefulBufC string;
    } val;
    */

    suit_envelope_key_t envelope_key = SUIT_ENVELOPE_KEY_INVALID;
    suit_manifest_key_t manifest_key = SUIT_MANIFEST_KEY_INVALID;
    suit_digest_t manifest_digest;
    suit_extracted_t extracted = {0};

    /* check the digests */
    QCBORDecode_Init(&context,
                     (UsefulBufC){suit_inputs->manifest.ptr, suit_inputs->manifest.len},
                     QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&context, &item);
    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
        error = QCBORDecode_PeekNext(&context, &item);
        if (error != QCBOR_SUCCESS) {
            goto error;
        }
        if (item.uLabelType == QCBOR_TYPE_TEXT_STRING) {
            /* integrated-payload */
            envelope_key = SUIT_INTEGRATED_PAYLOAD;
            if (extracted.payloads_len >= SUIT_MAX_ARRAY_LENGTH) {
                result = SUIT_ERR_NO_MEMORY;
                goto error;
            }
            extracted.payloads[extracted.payloads_len].key = item.label.string;
            QCBORDecode_GetByteString(&context, &extracted.payloads[extracted.payloads_len].bytes);
            extracted.payloads_len++;
        }
        else if (item.uLabelType == QCBOR_TYPE_INT64 || item.uLabelType == QCBOR_TYPE_UINT64) {
            envelope_key = item.label.int64;
            switch (envelope_key) {
            case SUIT_AUTHENTICATION:
                result = suit_process_authentication_wrapper(&context, suit_inputs, &manifest_digest);
                break;
            case SUIT_MANIFEST:
                if (manifest_digest.algorithm_id == SUIT_ALGORITHM_ID_INVALID) {
                    result = SUIT_ERR_AUTHENTICATION_POSITION;
                    goto error;
                }
                else {
                    QCBORDecode_GetNext(&context, &item);
                    result = suit_verify_item(&context, &item, &manifest_digest);
                    if (result != SUIT_SUCCESS) {
                        goto error;
                    }
                    result = suit_extract_manifest(item.val.string, &extracted, suit_callbacks);
                }
                break;
            case SUIT_DELEGATION:
                result = SUIT_ERR_NOT_IMPLEMENTED;
                goto error;

            /* Severed Members */
            case SUIT_SEVERED_INSTALL:
                if (extracted.install.ptr != NULL) {
                    result = SUIT_ERR_REDUNDANT;
                    goto error;
                }
                QCBORDecode_GetByteString(&context, &extracted.install);
                break;

            case SUIT_SEVERED_DEPENDENCY_RESOLUTION:
                if (extracted.dependency_resolution.ptr != NULL) {
                    result = SUIT_ERR_REDUNDANT;
                    goto error;
                }
                QCBORDecode_GetByteString(&context, &extracted.dependency_resolution);
                break;

            case SUIT_SEVERED_PAYLOAD_FETCH:
                if (extracted.payload_fetch.ptr != NULL) {
                    result = SUIT_ERR_REDUNDANT;
                    goto error;
                }
                QCBORDecode_GetByteString(&context, &extracted.payload_fetch);
                break;

            case SUIT_SEVERED_TEXT:
                if (extracted.text.ptr != NULL) {
                    result = SUIT_ERR_REDUNDANT;
                    goto error;
                }
                QCBORDecode_GetByteString(&context, &extracted.text);
                break;

            case SUIT_SEVERED_COSWID:
                if (extracted.coswid.ptr != NULL) {
                    result = SUIT_ERR_REDUNDANT;
                    goto error;
                }
                QCBORDecode_GetByteString(&context, &extracted.coswid);
                break;

            default:
                result = SUIT_ERR_NOT_IMPLEMENTED;
                goto error;
                break;
            }
        }
        else {
            result = SUIT_ERR_INVALID_TYPE_OF_KEY;
            goto error;
        }
    }
    QCBORDecode_ExitMap(&context);
    error = QCBORDecode_Finish(&context);
    if (error != QCBOR_SUCCESS) {
        goto out;
    }

    /* dependency-resolution */
    result = suit_process_command_sequence(SUIT_DEPENDENCY_RESOLUTION, suit_inputs, &extracted, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* payload-fetch */
    result = suit_process_command_sequence(SUIT_PAYLOAD_FETCH, suit_inputs, &extracted, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* install */
    result = suit_process_command_sequence(SUIT_INSTALL, suit_inputs, &extracted, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* validate */
    result = suit_process_command_sequence(SUIT_VALIDATE, suit_inputs, &extracted, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* load */
    result = suit_process_command_sequence(SUIT_LOAD, suit_inputs, &extracted, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* run */
    result = suit_process_command_sequence(SUIT_RUN, suit_inputs, &extracted, suit_callbacks);
    if (result != SUIT_SUCCESS) {
        goto error;
    }


#if 0
    QCBORDecode_Init(&context, ko, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&context, &item);
    size_t length = item.val.uCount;
    for (size_t i = 0; i < length; i++) {
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
            goto error;
        }
    }
    QCBORDecode_ExitMap(&context);
    error = QCBORDecode_Finish(&context);
    if (error != QCBOR_SUCCESS) {
        goto error;
    }
#endif

out:
    return result;

error:
    if (suit_callbacks->on_error != NULL || result != SUIT_ERR_ABORT) {
        suit_callbacks->on_error(
            (suit_on_error_args_t) {
                .level0 = envelope_key,
                .level1.manifest_key = manifest_key,
                .level2.condition_directive = SUIT_CONDITION_INVALID,
                .level3.parameter = SUIT_PARAMETER_INVALID,
                .qcbor_error = error,
                .suit_error = result
            }
        );
        return SUIT_ERR_ABORT;
    }
    return result;
}
