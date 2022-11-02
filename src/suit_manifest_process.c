/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*!
    \file   suit_manifest_process.c

    \brief  This implements libcsuit processing

    Call suit_process_envelopes() to process whole SUIT manifests at once.
    One or more manifests may depend other manifests.
 */

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "csuit/suit_common.h"
#include "csuit/suit_manifest_process.h"
#include "csuit/suit_manifest_print.h"

suit_err_t suit_set_parameters(QCBORDecodeContext *context,
                               const suit_con_dir_key_t directive,
                               suit_parameter_args_t *parameters,
                               const suit_index_t index) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    QCBORDecode_EnterMap(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        goto error;
    }
    suit_parameter_key_t parameter;

    union {
        uint64_t u64;
        int64_t i64;
        UsefulBufC str;
        bool b;
        suit_digest_t digest;
    } val;

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
            QCBORDecode_GetTextString(context, &val.str);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_URI) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_URI;
                    parameters[tmp_index].uri_list_len = 1;
                    parameters[tmp_index].uri_list[0] = val.str;
                }
            }
            break;
        case SUIT_PARAMETER_IMAGE_DIGEST:
            QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
            result = suit_decode_digest_from_item(SUIT_DECODE_MODE_STRICT, context, &item, true, &val.digest);
            QCBORDecode_ExitBstrWrapped(context);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_IMAGE_DIGEST) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_IMAGE_DIGEST;
                    parameters[tmp_index].image_digest = val.digest;
                }
            }
            break;
        case SUIT_PARAMETER_IMAGE_SIZE:
            QCBORDecode_GetUInt64(context, &val.u64);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_IMAGE_SIZE) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_IMAGE_SIZE;
                    parameters[tmp_index].image_size = val.u64;
                }
            }
            break;
        case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            QCBORDecode_GetByteString(context, &val.str);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_VENDOR_IDENTIFIER) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_VENDOR_IDENTIFIER;
                    parameters[tmp_index].vendor_id = val.str;
                }
            }
            break;
        case SUIT_PARAMETER_CLASS_IDENTIFIER:
            QCBORDecode_GetByteString(context, &val.str);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_CLASS_IDENTIFIER) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_CLASS_IDENTIFIER;
                    parameters[tmp_index].class_id = val.str;
                }
            }
            break;
        case SUIT_PARAMETER_SOFT_FAILURE:
            QCBORDecode_GetBool(context, &val.b);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_SOFT_FAILURE) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_SOFT_FAILURE;
                    parameters[tmp_index].soft_failure = (val.b) ? SUIT_PARAMETER_TRUE : SUIT_PARAMETER_FALSE;
                }
            }
            break;
        case SUIT_PARAMETER_SOURCE_COMPONENT:
            QCBORDecode_GetUInt64(context, &val.u64);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_SOURCE_COMPONENT) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_SOURCE_COMPONENT;
                    parameters[tmp_index].source_component = val.u64;
                }
            }
            break;
        case SUIT_PARAMETER_COMPONENT_SLOT:
            QCBORDecode_GetUInt64(context, &val.u64);
            for (size_t j = 0; j < index.len; j++) {
                uint8_t tmp_index = index.index[j].val + (index.is_dependency) * SUIT_MAX_COMPONENT_NUM;
                if (!(parameters[tmp_index].exists & SUIT_PARAMETER_CONTAINS_COMPONENT_SLOT) || directive == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS) {
                    parameters[tmp_index].exists |= SUIT_PARAMETER_CONTAINS_COMPONENT_SLOT;
                    parameters[tmp_index].component_slot = val.u64;
                }
            }
            break;
        case SUIT_PARAMETER_USE_BEFORE:

        case SUIT_PARAMETER_STRICT_ORDER:

        case SUIT_PARAMETER_ENCRYPTION_INFO:
        case SUIT_PARAMETER_INVOKE_ARGS:

        case SUIT_PARAMETER_DEVICE_IDENTIFIER:
        case SUIT_PARAMETER_MINIMUM_BATTERY:
        case SUIT_PARAMETER_UPDATE_PRIORITY:
        case SUIT_PARAMETER_VERSION:
        case SUIT_PARAMETER_WAIT_INFO:
        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
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
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = SUIT_COMMON,
                .level2.common_key = SUIT_SHARED_SEQUENCE,
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

suit_payload_t* suit_index_to_payload(suit_extracted_t *extracted,
                                      suit_index_t index) {
    if (index.len != 1) {
        return NULL;
    }
    for (size_t i = 0; i < extracted->payloads.len; i++) {
        if (memcmp(&extracted->payloads.payload[i].index, &index, sizeof(suit_index_t)) == 0) {
            return &extracted->payloads.payload[i];
        }
    }
    return NULL;
}

suit_payload_t* suit_key_to_payload(suit_extracted_t *extracted,
                                    UsefulBufC key) {
    for (size_t i = 0; i < extracted->payloads.len; i++) {
        if (extracted->payloads.payload[i].key.len != key.len) {
            continue;
        }
        if (extracted->payloads.payload[i].key.ptr == key.ptr) {
            return &extracted->payloads.payload[i];
        }
        else if (memcmp(extracted->payloads.payload[i].key.ptr, key.ptr, key.len) == 0) {
            return &extracted->payloads.payload[i];
        }
    }
    return NULL;
}

suit_err_t suit_process_dependency(suit_extracted_t *extracted,
                                   suit_index_t dependency_index,
                                   const suit_inputs_t *suit_inputs) {
    suit_payload_t *payload = suit_index_to_payload(extracted, dependency_index);
    if (payload == NULL) {
        return SUIT_ERR_NO_ARGUMENT;
    }
    suit_inputs_t tmp_inputs = *suit_inputs;
    tmp_inputs.manifest = payload->bytes;
    return suit_process_envelope(&tmp_inputs);
}

suit_err_t suit_set_index(QCBORDecodeContext *context,
                          const suit_extracted_t *extracted,
                          suit_index_t *index) {
    union {
        uint64_t u64;
        bool b;
    } val;

    *index = (suit_index_t){0};
    index->is_dependency = 0; /* TODO: is_dependency should be removed */

    QCBORItem item;
    QCBORError error;
    QCBORDecode_PeekNext(context, &item);
    switch (item.uDataType) {
    case QCBOR_TYPE_UINT64:
    case QCBOR_TYPE_INT64:
        QCBORDecode_GetUInt64(context, &val.u64);
        if (val.u64 > UINT8_MAX) {
            return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        }
        index->len = 1;
        index->index[0].val = (uint8_t)val.u64;
        break;
    case QCBOR_TYPE_TRUE:
        index->len = extracted->components.len;
        for (uint8_t i = 0; i < index->len; i++) {
            index->index[i].val = i;
        }
        /* fall through */
    case QCBOR_TYPE_FALSE:
        QCBORDecode_GetBool(context, &val.b);
        break;
    case QCBOR_TYPE_ARRAY:
        QCBORDecode_EnterArray(context, &item);
        if (item.val.uCount > SUIT_MAX_COMPONENT_NUM) {
            return SUIT_ERR_NO_MEMORY;
        }
        index->len = item.val.uCount;
        for (size_t i = 0; i < index->len; i++) {
            QCBORDecode_GetUInt64(context, &val.u64);
            if (val.u64 > UINT8_MAX) {
                return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
            }
            index->index[i].val = (uint8_t)val.u64;
        }
        QCBORDecode_ExitArray(context);
        error = QCBORDecode_GetError(context);
        if (error != QCBOR_SUCCESS) {
            return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        }
    default:
        return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_process_command_sequence_buf(suit_extracted_t *extracted,
                                             const suit_manifest_key_t command_key,
                                             UsefulBufC buf,
                                             suit_parameter_args_t parameters[],
                                             suit_inputs_t *suit_inputs) {
    suit_err_t result = SUIT_SUCCESS;
    suit_index_t index = {.is_dependency = 0, .len = 1, .index[0].val = 0};
    suit_con_dir_key_t condition_directive_key = SUIT_CONDITION_INVALID;
    suit_rep_policy_t report;
    union {
        struct {
            suit_fetch_args_t fetch;
            suit_fetch_ret_t fret;
        };
        suit_store_args_t store;
        suit_copy_args_t copy;
        suit_invoke_args_t invoke;
    } args;
    union {
        uint64_t u64;
        int64_t i64;
        UsefulBufC buf;
        bool b;
    } val;

    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    QCBORDecode_Init(&context, buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&context, &item);
    const size_t length = item.val.uCount;
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
            // TODO: support also bool or [ + uint ] index
            result = suit_set_index(&context, extracted, &index);
            break;
        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            // TODO: support also bool or [ + uint ] index
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, parameters, index);
            break;
        case SUIT_DIRECTIVE_SET_PARAMETERS:
            // TODO: support also bool or [ + uint ] index
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_SET_PARAMETERS, parameters, index);
            break;
        case SUIT_DIRECTIVE_FETCH:
            QCBORDecode_GetUInt64(&context, &report.val);
            for (size_t j = 0; j < index.len; j++) {
                const uint8_t tmp_index = index.index[j].val + index.is_dependency * SUIT_MAX_COMPONENT_NUM;
                if (parameters[tmp_index].uri_list_len == 0) {
                    result = SUIT_ERR_NO_ARGUMENT;
                    goto error;
                }
                if (parameters[tmp_index].uri_list[0].len >= SUIT_MAX_NAME_LENGTH) {
                    result = SUIT_ERR_NO_MEMORY;
                    goto error;
                }

                suit_payload_t *payload = suit_key_to_payload(extracted, parameters[tmp_index].uri_list[0]);
                if (payload == NULL) {
                    if (extracted->payloads.len >= SUIT_MAX_ARRAY_LENGTH) {
                        result = SUIT_ERR_NO_MEMORY;
                        goto error;
                    }

                    args.fetch = (suit_fetch_args_t){0};
                    args.fetch.report = report;
                    if (index.is_dependency) {
                        args.fetch.key = SUIT_DEPENDENCIES;
                        args.fetch.dst.dependency = extracted->dependencies.dependency[index.index[j].val];
                    }
                    else {
                        args.fetch.key = SUIT_COMPONENTS;
                        args.fetch.dst.component_identifier = extracted->components.comp_id[index.index[j].val];
                    }
                    memcpy(args.fetch.uri, parameters[tmp_index].uri_list[0].ptr, parameters[tmp_index].uri_list[0].len);
                    args.fetch.uri[parameters[tmp_index].uri_list[0].len] = '\0';
                    args.fetch.uri_len = parameters[tmp_index].uri_list[0].len;
                    size_t buf_size = (parameters[tmp_index].image_size > 0) ? parameters[tmp_index].image_size : suit_inputs->left_len;
                    if (buf_size > suit_inputs->left_len) {
                        result = SUIT_ERR_NO_MEMORY;
                        goto error;
                    }
                    args.fetch.ptr = suit_inputs->ptr + (SUIT_MAX_DATA_SIZE - suit_inputs->left_len); //;
                    args.fetch.buf_len = buf_size;
                    uint8_t *buf_ptr = &suit_inputs->buf[SUIT_MAX_DATA_SIZE - suit_inputs->left_len];

                    /* store the fetched payload into args.fetch.ptr */
                    result = suit_fetch_callback(args.fetch, &args.fret);
                    if (result != SUIT_SUCCESS) {
                        goto error;
                    }
                    if (args.fetch.buf_len < args.fret.buf_len) {
                        result = SUIT_ERR_NO_MEMORY;
                        goto error;
                    }
                    suit_inputs->left_len -= args.fret.buf_len;
                    payload = &extracted->payloads.payload[extracted->payloads.len];
                    extracted->payloads.len++;
                    payload->bytes.ptr = buf_ptr;
                    payload->bytes.len = args.fret.buf_len;

                    if (payload->bytes.ptr != args.fetch.ptr) {
                        /* the buffer is different between the caller and callee */
                        memcpy(buf_ptr, args.fetch.ptr, payload->bytes.len);
                    }

                    payload->key = parameters[tmp_index].uri_list[0];
                    payload->index.len = 1;
                    payload->index.is_dependency = index.is_dependency;
                    payload->index.index[0].val = index.index[j].val;
                }
                else {
                    /* already handled with integrated-payload or integrated-dependency */
                    args.store = (suit_store_args_t){0};
                    args.store.report = report;
                    if (index.is_dependency) {
                        args.store.key = SUIT_DEPENDENCIES;
                        args.store.dst.dependency = extracted->dependencies.dependency[index.index[j].val];
                    }
                    else {
                        args.store.key = SUIT_COMPONENTS;
                        args.store.dst.component_identifier = extracted->components.comp_id[index.index[j].val];
                    }
                    UsefulBuf buf = UsefulBuf_Unconst(payload->bytes);
                    args.store.ptr = buf.ptr;
                    args.store.buf_len = buf.len;
                    result = suit_store_callback(args.store);
                    if (result != SUIT_SUCCESS) {
                        goto error;
                    }

                    payload->key = parameters[tmp_index].uri_list[0];
                    payload->index.len = 1;
                    payload->index.is_dependency = index.is_dependency;
                    payload->index.index[0].val = index.index[j].val;
                }
            }
            break;
        case SUIT_DIRECTIVE_COPY:
            QCBORDecode_GetUInt64(&context, &val.u64);
            for (size_t j = 0; j < index.len; j++) {
                const uint8_t tmp_index = index.index[j].val + index.is_dependency * SUIT_MAX_COMPONENT_NUM;

                args.copy = (suit_copy_args_t){0};
                args.copy.info_key = SUIT_INFO_DEFAULT;
                /* TODO solve SUIT_INFO_ENCRYPTION_INFO */

                args.copy.report.val = val.u64;
                args.copy.src = extracted->components.comp_id[parameters[tmp_index].source_component];
                args.copy.dst = extracted->components.comp_id[tmp_index];
                result = suit_copy_callback(args.copy);
            }
            break;
        case SUIT_DIRECTIVE_INVOKE:
            QCBORDecode_GetUInt64(&context, &val.u64);
            for (size_t j = 0; j < index.len; j++) {
                const uint8_t tmp_index = index.index[j].val + index.is_dependency * SUIT_MAX_COMPONENT_NUM;

                if (extracted->components.len < tmp_index || extracted->components.comp_id[tmp_index].len == 0) {
                    result = SUIT_ERR_NO_ARGUMENT;
                    goto error;
                }
                args.invoke = (suit_invoke_args_t){0};
                args.invoke.report.val = val.u64;

                args.invoke.component_identifier = extracted->components.comp_id[tmp_index];
                args.invoke.args_len = parameters[tmp_index].invoke_args.len;
                if (args.invoke.args_len > 0) {
                    memcpy(args.invoke.args, parameters[tmp_index].invoke_args.ptr, args.invoke.args_len);
                }
                result = suit_invoke_callback(args.invoke);
            }
            break;
        case SUIT_DIRECTIVE_TRY_EACH:
            QCBORDecode_EnterArray(&context, &item);
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                goto error;
            }
            const size_t try_count = item.val.uCount;
            bool orig_soft_failures[SUIT_MAX_COMPONENT_NUM];
            for (size_t j = 0; j < SUIT_MAX_COMPONENT_NUM; j++) {
                orig_soft_failures[j] = parameters[j].soft_failure;
            }
            bool done = false;
            for (size_t j = 0; j < try_count; j++) {
                QCBORDecode_GetNext(&context, &item);
                if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                    if (!done) {
                        result = suit_process_command_sequence_buf(extracted, SUIT_COMMON, item.val.string, parameters, NULL);
                        if (result == SUIT_SUCCESS) {
                            done = true;
                        }
                    }
                }
                else if (item.uDataType == QCBOR_TYPE_NULL && j + 1 == try_count) {
                    /* continue without error, see #8.7.7.3 */
                    done = true;
                    break;
                }
                else {
                    result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                    goto error;
                }
            }
            for (size_t j = 0; j < SUIT_MAX_COMPONENT_NUM; j++) {
                parameters[j].soft_failure = orig_soft_failures[j];
            }
            QCBORDecode_ExitArray(&context);
            if (!done) {
                result = SUIT_ERR_TRY_OUT;
                goto error;
            }
            break;
        case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
            if (!index.is_dependency) {
                result = SUIT_ERR_INVALID_KEY;
                goto error;
            }
            // TODO:
            QCBORDecode_GetUInt64(&context, &report.val);
            result = suit_process_dependency(extracted, index, suit_inputs);
            break;
        case SUIT_DIRECTIVE_UNLINK:
            QCBORDecode_GetUInt64(&context, &report.val);
            for (size_t j = 0; j < index.len; j++) {
                const uint8_t tmp_index = index.index[j].val + index.is_dependency * SUIT_MAX_COMPONENT_NUM;

                if (extracted->components.len < tmp_index || extracted->components.comp_id[tmp_index].len == 0) {
                    result = SUIT_ERR_NO_ARGUMENT;
                    goto error;
                }
                args.store = (suit_store_args_t){0};
                args.store.report = report;
                if (index.is_dependency) {
                    args.store.key = SUIT_DEPENDENCIES;
                    args.store.dst.dependency = extracted->dependencies.dependency[index.index[j].val];
                }
                else {
                    args.store.key = SUIT_COMPONENTS;
                    args.store.dst.component_identifier = extracted->components.comp_id[index.index[j].val];
                }
                args.store.ptr = NULL;
                args.store.buf_len = 0;
                result = suit_store_callback(args.store);
            }
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

        case SUIT_DIRECTIVE_WAIT:
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

    switch (command_key) {
    case SUIT_INSTALL:
        break;
    case SUIT_VALIDATE:
        break;
    default:
        break;
    }
    return result;

error:
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = command_key,
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

suit_err_t suit_process_shared_sequence(suit_extracted_t *extracted,
                                        suit_parameter_args_t parameters[]) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;
    suit_con_dir_key_t condition_directive_key;
    suit_index_t index = {.is_dependency = 0, .len = 1, .index[0].val = 0};
    suit_rep_policy_t report;
    union {
        uint64_t u64;
        int64_t i64;
        UsefulBufC buf;
        bool b;
    } val;

    QCBORDecode_Init(&context, extracted->shared_sequence, QCBOR_DECODE_MODE_NORMAL);
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
            // TODO: support also bool or [ + uint ] index
            QCBORDecode_GetUInt64(&context, &val.u64);
            if (val.u64 >= extracted->components.len) {
                result = SUIT_ERR_NO_MEMORY;
                goto error;
            }
            if (val.u64 > UINT8_MAX) {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                goto error;
            }
            index.is_dependency = 0;
            index.len = 1;
            index.index[0].val = (uint8_t)val.u64;
            break;

        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            // TODO: support also bool or [ + uint ] index
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, parameters, index);
            break;
        case SUIT_DIRECTIVE_SET_PARAMETERS:
            // TODO: support also bool or [ + uint ] index
            result = suit_set_parameters(&context, SUIT_DIRECTIVE_SET_PARAMETERS, parameters, index);
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
        case SUIT_DIRECTIVE_TRY_EACH:
            QCBORDecode_EnterArray(&context, &item);
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                goto error;
            }
            const size_t try_count = item.val.uCount;
            bool orig_soft_failures[SUIT_MAX_COMPONENT_NUM];
            for (size_t j = 0; j < SUIT_MAX_COMPONENT_NUM; j++) {
                orig_soft_failures[j] = parameters[j].soft_failure;
            }
            bool done = false;
            for (size_t j = 0; j < try_count; j++) {
                QCBORDecode_GetNext(&context, &item);
                if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                    if (!done) {
                        result = suit_process_command_sequence_buf(extracted, SUIT_COMMON, item.val.string, parameters, NULL);
                        if (result == SUIT_SUCCESS) {
                            done = true;
                        }
                    }
                }
                else if (item.uDataType == QCBOR_TYPE_NULL && j + 1 == try_count) {
                    /* continue without error, see #8.7.7.3 */
                    done = true;
                    break;
                }
                else {
                    result = SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
                    goto error;
                }
            }
            for (size_t j = 0; j < SUIT_MAX_COMPONENT_NUM; j++) {
                parameters[j].soft_failure = orig_soft_failures[j];
            }
            QCBORDecode_ExitArray(&context);
            if (!done) {
                result = SUIT_ERR_TRY_OUT;
                goto error;
            }
            break;
        case SUIT_DIRECTIVE_RUN_SEQUENCE:
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
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = SUIT_COMMON,
                .level2.common_key = SUIT_SHARED_SEQUENCE,
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

suit_err_t suit_process_common_and_command_sequence(suit_extracted_t *extracted,
                                                    const suit_manifest_key_t command_key,
                                                    suit_inputs_t *suit_inputs) {
    suit_err_t result = SUIT_SUCCESS;
    suit_parameter_args_t parameters[SUIT_MAX_COMPONENT_NUM + SUIT_MAX_DEPENDENCY_NUM];

    UsefulBufC command_buf;
    switch (command_key) {
    case SUIT_DEPENDENCY_RESOLUTION:
        command_buf = extracted->dependency_resolution;
        break;
    case SUIT_PAYLOAD_FETCH:
        command_buf = extracted->payload_fetch;
        break;
    case SUIT_INSTALL:
        command_buf = extracted->install;
        break;
    case SUIT_VALIDATE:
        command_buf = extracted->validate;
        break;
    case SUIT_LOAD:
        command_buf = extracted->load;
        break;
    case SUIT_INVOKE:
        command_buf = extracted->invoke;
        break;
    default:
        return SUIT_ERR_INVALID_KEY;
    }
    if (command_buf.len == 0 || command_buf.ptr == NULL) {
        /* no need to execute shared_sequence */
        return SUIT_SUCCESS;
    }

    memset(parameters, 0, sizeof(parameters));
    result = suit_process_shared_sequence(extracted, parameters);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    return suit_process_command_sequence_buf(extracted, command_key, command_buf, parameters, suit_inputs);

error:
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
                .level0 = SUIT_MANIFEST,
                .level1.manifest_key = command_key,
                .level2.condition_directive = SUIT_CONDITION_INVALID,
                .level3.parameter = SUIT_PARAMETER_INVALID,
                .qcbor_error = QCBOR_SUCCESS,
                .suit_error = result,
                .report = {0}
            }
        );
        return SUIT_ERR_ABORT;
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
                                               const suit_inputs_t *suit_inputs,
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
                               suit_extracted_t *extracted) {
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
        case SUIT_SHARED_SEQUENCE:
            QCBORDecode_GetByteString(context, &extracted->shared_sequence);
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
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
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


suit_err_t suit_extract_manifest(suit_extracted_t *extracted) {
    suit_err_t result = SUIT_SUCCESS;
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error = QCBOR_SUCCESS;

    suit_manifest_key_t manifest_key;

    QCBORDecode_Init(&context, extracted->manifest, QCBOR_DECODE_MODE_NORMAL);
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
            result = suit_extract_common(&context, extracted);
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
        case SUIT_INVOKE:
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecode_GetByteString(&context, &extracted->invoke);
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
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
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
suit_err_t suit_process_envelope(suit_inputs_t *suit_inputs) {
    QCBORDecodeContext context;
    QCBORError error = QCBOR_SUCCESS;
    QCBORItem item;
    suit_err_t result = SUIT_SUCCESS;

    suit_envelope_key_t envelope_key = SUIT_ENVELOPE_KEY_INVALID;
    suit_manifest_key_t manifest_key = SUIT_MANIFEST_KEY_INVALID;
    suit_digest_t manifest_digest;
    suit_extracted_t extracted = {0};

    /* extract items */
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
            if (extracted.payloads.len >= SUIT_MAX_ARRAY_LENGTH) {
                result = SUIT_ERR_NO_MEMORY;
                goto error;
            }
            extracted.payloads.payload[extracted.payloads.len].key = item.label.string;
            QCBORDecode_GetByteString(&context, &extracted.payloads.payload[extracted.payloads.len].bytes);
            extracted.payloads.len++;
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
                    extracted.manifest = item.val.string;
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

            case SUIT_SEVERED_WORKAROUND_TEXT:
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

    result = suit_extract_manifest(&extracted);

    /* TODO: check digests */


    /* dependency-resolution */
    result = suit_process_common_and_command_sequence(&extracted, SUIT_DEPENDENCY_RESOLUTION, suit_inputs);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* payload-fetch */
    result = suit_process_common_and_command_sequence(&extracted, SUIT_PAYLOAD_FETCH, suit_inputs);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* install */
    result = suit_process_common_and_command_sequence(&extracted, SUIT_INSTALL, suit_inputs);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* validate */
    result = suit_process_common_and_command_sequence(&extracted, SUIT_VALIDATE, suit_inputs);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* load */
    result = suit_process_common_and_command_sequence(&extracted, SUIT_LOAD, suit_inputs);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

    /* invoke */
    result = suit_process_common_and_command_sequence(&extracted, SUIT_INVOKE, suit_inputs);
    if (result != SUIT_SUCCESS) {
        goto error;
    }

out:
    return result;

error:
    if (result != SUIT_ERR_ABORT) {
        suit_report_callback(
            (suit_report_args_t) {
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
