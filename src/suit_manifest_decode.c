/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_cose.h"
#include "suit_digest.h"
#include <inttypes.h>

int32_t suit_qcbor_get_next(QCBORDecodeContext *message, QCBORItem *item, uint8_t data_type) {
    QCBORError error;
    error = QCBORDecode_GetNext(message, item);
    switch (error) {
        case QCBOR_SUCCESS:
            break;
        case QCBOR_ERR_NO_MORE_ITEMS:
            return SUIT_NO_MORE_ITEMS;
        default:
            return SUIT_FATAL_ERROR;
    }
    if (data_type != QCBOR_TYPE_ANY && item->uDataType != data_type) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    return SUIT_SUCCESS;
}

int32_t suit_qcbor_get(QCBORDecodeContext *message, QCBORItem *item, bool next, uint8_t data_type) {
    if (next) {
        return suit_qcbor_get_next(message, item, data_type);
    }
    else if (data_type != QCBOR_TYPE_ANY && item->uDataType != data_type) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    return SUIT_SUCCESS;
}

bool suit_qcbor_value_is_uint64(QCBORItem *item) {
    if (item->uDataType == QCBOR_TYPE_INT64) {
        if (item->val.int64 < 0) {
            return false;
        }
        /* there is no need to cast int64_t [0, INT32_MAX] value into uint64_t in the union */
    }
    else if (item->uDataType != QCBOR_TYPE_UINT64) {
        return false;
    }
    return true;
}

bool suit_qcbor_value_is_uint32(QCBORItem *item) {
    switch (item->uDataType) {
        case QCBOR_TYPE_INT64:
            if (item->val.int64 < 0 || item->val.int64 > UINT32_MAX) {
                return false;
            }
            break;
        case QCBOR_TYPE_UINT64:
            if (item->val.uint64 > UINT32_MAX) {
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

int32_t suit_qcbor_get_next_uint(QCBORDecodeContext *message, QCBORItem *item) {
    int32_t result = suit_qcbor_get_next(message, item, QCBOR_TYPE_ANY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    return (suit_qcbor_value_is_uint64(item)) ? SUIT_SUCCESS : SUIT_INVALID_TYPE_OF_ARGUMENT;
}

/*
 * counts the CBOR binary offset between the CBOR type and length declaration
 * and current cursor = UsefulInputBuf_Tell(&context.InBuf)
 * note that with INT64, UINT64, TEXT_STRING, and BYTE_STRING,
 * the current cursor is tail of the value,
 * but with ARRAY, MAP, MAP_AS_ARRAY,
 * the current cursor is tail of the type and length declaration.
 */
size_t suit_qcbor_calc_rollback(QCBORItem *item) {
    uint8_t type = item->uDataType;
    if (item->uDataType == QCBOR_TYPE_INT64 && suit_qcbor_value_is_uint64(item)) {
        type = QCBOR_TYPE_UINT64;
    }

    switch (type) {
        case QCBOR_TYPE_UINT64:
            if (item->val.uint64 <= 23) {
                return 1;
            }
            else if (item->val.uint64 <= UINT8_MAX) {
                return 2;
            }
            else if (item->val.uint64 <= UINT16_MAX) {
                return 3;
            }
            else if (item->val.uint64 <= UINT32_MAX) {
                return 5;
            }
            return 9;
        case QCBOR_TYPE_INT64:
            if (item->val.int64 + 1 + 23 >= 0) {
                return 1;
            }
            else if (item->val.int64 + 1 + UINT8_MAX >= 0) {
                return 2;
            }
            else if (item->val.int64 + 1 + UINT16_MAX >= 0) {
                return 3;
            }
            else if (item->val.int64 + 1 + UINT32_MAX >= 0) {
                return 5;
            }
            return 9;
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TEXT_STRING:
            if (item->val.string.len < 24) {
                return 1 + item->val.string.len;
            }
            else if (item->val.string.len <= UINT8_MAX) {
                return 2 + item->val.string.len;
            }
            else if (item->val.string.len <= UINT16_MAX) {
                return 3 + item->val.string.len;
            }
            else if (item->val.string.len <= UINT32_MAX) {
                return 5 + item->val.string.len;
            }
            return 9 + item->val.string.len;
        case QCBOR_TYPE_ARRAY:
        case QCBOR_TYPE_MAP:
            if (item->val.uCount < 24) {
                return 1;
            }
            else if (item->val.uCount < UINT8_MAX) {
                return 2;
            }
            else if (item->val.uCount < UINT16_MAX) {
                return 3;
            }
            else if (item->val.uCount < UINT32_MAX) {
                return 5;
            }
            return 9;
    }
    return 0;
}

bool suit_qcbor_skip_any(QCBORDecodeContext *message, QCBORItem *item);

bool suit_qcbor_skip_array_and_map(QCBORDecodeContext *message, QCBORItem *item) {
    if (item->uDataType != QCBOR_TYPE_ARRAY && item->uDataType != QCBOR_TYPE_MAP) {
        return false;
    }
    size_t array_size = item->val.uCount;
    for (size_t i = 0; i < array_size; i++) {
        int32_t result = suit_qcbor_get_next(message, item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return false;
        }
        if (!suit_qcbor_skip_any(message, item)) {
            return false;
        }
    }
    return true;
}

bool suit_qcbor_skip_any(QCBORDecodeContext *message, QCBORItem *item) {
    switch (item->uDataType) {
        case QCBOR_TYPE_ARRAY:
        case QCBOR_TYPE_MAP:
            if (!suit_qcbor_skip_array_and_map(message, item)) {
                return false;
            }
            break;
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TEXT_STRING:
            break;
        default:
            return false;
    }
    return true;
}

int32_t suit_set_digest_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_digest_t *digest) {
    digest->algorithm_id = SUIT_ALGORITHM_ID_INVALID;
    digest->bytes.len = 0;
    //digest->extension.len = 0;
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t ext_len = (item->val.uCount > 2) ? item->val.uCount - 2 : 0;

    result = suit_qcbor_get_next_uint(context, item);
    if (!suit_continue(mode, result)) {
        suit_debug_print(context, item, "suit_set_digest@algorithm-id", QCBOR_TYPE_INT64);
        return result;
    }
    digest->algorithm_id = item->val.uint64;

    result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
    if (!suit_continue(mode, result)) {
        suit_debug_print(context, item, "suit_set_digest@digest-bytes", QCBOR_TYPE_BYTE_STRING);
        return result;
    }
    if (result == SUIT_SUCCESS) {
        digest->bytes.ptr = item->val.string.ptr;
        digest->bytes.len = item->val.string.len;
    }

    for (size_t i = 0; i < ext_len; i++) {
        // TODO
        suit_debug_print(context, item, "suit_set_digest skipping SUIT_Digest-extensions", QCBOR_TYPE_ANY);
        if (!suit_continue(mode, SUIT_NOT_IMPLEMENTED)) {
            return SUIT_NOT_IMPLEMENTED;
        }
        if (!suit_qcbor_skip_any(context, item)) {
            return SUIT_NO_MORE_ITEMS;
        }
    }
    return SUIT_SUCCESS;
}

int32_t suit_set_digest(uint8_t mode, suit_buf_t *buf, suit_digest_t *digest) {
    QCBORDecodeContext digest_context;
    QCBORItem item;
    QCBORDecode_Init(&digest_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_digest_from_item(mode, &digest_context, &item, true, digest);
    QCBORError error = QCBORDecode_Finish(&digest_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_digest_from_bstr(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_digest_t *digest) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    suit_buf_t buf;
    buf.ptr = item->val.string.ptr;
    buf.len = item->val.string.len;
    return suit_set_digest(mode, &buf, digest);
}

int32_t suit_set_parameters_list_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_parameters_list_t *params_list) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    params_list->len = item->val.uCount;
    for (size_t i = 0; i < params_list->len; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            goto out;
        }
        params_list->params[i].label = item->label.uint64;
        switch (params_list->params[i].label) {
            case SUIT_PARAMETER_COMPONENT_OFFSET:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_COMPRESSION_INFO:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                if (!suit_qcbor_value_is_uint64(item)) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                params_list->params[i].value.uint64 = item->val.uint64;
                break;
            case SUIT_PARAMETER_URI:
                if (item->uDataType != QCBOR_TYPE_TEXT_STRING) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                params_list->params[i].value.string.ptr = item->val.string.ptr;
                params_list->params[i].value.string.len = item->val.string.len;
                break;
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                params_list->params[i].value.string.ptr = item->val.string.ptr;
                params_list->params[i].value.string.len = item->val.string.len;
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                result = suit_set_digest_from_bstr(mode, context, item, false, &params_list->params[i].value.digest);
                break;

            case SUIT_PARAMETER_USE_BEFORE:

            case SUIT_PARAMETER_STRICT_ORDER:
            case SUIT_PARAMETER_SOFT_FAILURE:

            case SUIT_PARAMETER_ENCRYPTION_INFO:
            case SUIT_PARAMETER_UNPACK_INFO:
            case SUIT_PARAMETER_RUN_ARGS:

            case SUIT_PARAMETER_DEVICE_IDENTIFIER:
            case SUIT_PARAMETER_MINIMUM_BATTERY:
            case SUIT_PARAMETER_UPDATE_PRIORITY:
            case SUIT_PARAMETER_VERSION:
            case SUIT_PARAMETER_WAIT_INFO:
            case SUIT_PARAMETER_URI_LIST:
            default:
                suit_debug_print(context, item, "suit_set_parameters_list", QCBOR_TYPE_NONE);
                result = SUIT_NOT_IMPLEMENTED;
                if (!suit_qcbor_skip_any(context, item)) {
                    result = SUIT_FATAL_ERROR;
                }
                break;
        }
out:
        if (!suit_continue(mode, result)) {
            if (!(mode & SUIT_DECODE_MODE_PRESERVE_ON_ERROR)) {
                params_list->len = 0;
            }
            break;
        }
    }
    return result;
}

int32_t suit_set_command_custom_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, int64_t label, suit_command_sequence_item_t *cmd_item) {
    // TODO:
    return SUIT_NOT_IMPLEMENTED;
}

bool is_suit_directive_only(uint64_t label) {
    /* NOTE:
     * SUIT_Common_Commands is a subset of SUIT_Directive
     */
    switch (label) {
        /* {SUIT_Directive - SUIT_Common_Commands} should not come */
        case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
        case SUIT_DIRECTIVE_FETCH:
        case SUIT_DIRECTIVE_COPY:
        case SUIT_DIRECTIVE_SWAP:
        case SUIT_DIRECTIVE_RUN:
        case SUIT_DIRECTIVE_FETCH_URI_LIST:
            return true;
    }
    return false;
}

int32_t suit_set_command_common_sequence_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_command_sequence_t *cmd_seq, bool is_common_sequence) {
    /* NOTE:
     * SUIT_Common_Sequence  = [ + (SUIT_Condition // SUIT_Common_Commands) ]
     * SUIT_Command_Sequence = [ + (SUIT_Condition // SUIT_Directive // SUIT_Command_Custom ] */
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t array_count = item->val.uCount;
    cmd_seq->len = 0;
    for (size_t i = 0; i < array_count; i += 2) {
        if (cmd_seq->len >= SUIT_MAX_ARRAY_LENGTH) {
            result = SUIT_NO_MEMORY;
            break;
        }
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_INT64);
        if (result != SUIT_SUCCESS) {
            break;
        }

        int64_t label = item->val.int64;

        // NOTE: assert every label is in [INT64_MIN, INT64_MAX]
        if (label < 0) {
            /* SUIT_Command_Custom */
            result = suit_set_command_custom_from_item(mode, context, item, label, &cmd_seq->commands[cmd_seq->len]);
            if (result == SUIT_SUCCESS) {
                cmd_seq->len++;
            }
        }
        else {
            /* SUIT_Condition // SUIT_Directive */
            if (is_common_sequence && is_suit_directive_only(label)) {
                /* SUIT_Command_Custom should not come, so skip them */
                result = SUIT_FATAL_ERROR;
                if (!suit_continue(mode, result)) {
                    break;
                }
            }
            switch (label) {
                case SUIT_CONDITION_VENDOR_IDENTIFIER:
                case SUIT_CONDITION_CLASS_IDENTIFIER:
                case SUIT_CONDITION_IMAGE_MATCH:
                case SUIT_CONDITION_COMPONENT_OFFSET:
                case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
                case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
                case SUIT_DIRECTIVE_FETCH:
                case SUIT_DIRECTIVE_COPY:
                case SUIT_DIRECTIVE_RUN:
                    result = suit_qcbor_get_next_uint(context, item);
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                    if (result == SUIT_SUCCESS) {
                        cmd_seq->commands[cmd_seq->len].label = label;
                        cmd_seq->commands[cmd_seq->len].value.uint64 = item->val.uint64;
                        cmd_seq->len++;
                    }
                    else if (result != SUIT_INVALID_TYPE_OF_ARGUMENT) {
                        if (suit_qcbor_skip_any(context, item)) {
                            result = SUIT_FATAL_ERROR;
                        }
                    }
                    break;
                case SUIT_DIRECTIVE_SET_PARAMETERS:
                case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                    result = suit_set_parameters_list_from_item(mode, context, item, true, &cmd_seq->commands[cmd_seq->len].value.params_list);
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                    if (result == SUIT_SUCCESS) {
                        cmd_seq->commands[cmd_seq->len].label = label;
                        cmd_seq->len++;
                    }
                    else if (result == SUIT_INVALID_TYPE_OF_ARGUMENT) {
                        if (!suit_qcbor_skip_any(context, item)) {
                            result = SUIT_FATAL_ERROR;
                        }
                    }
                    break;
                case SUIT_DIRECTIVE_TRY_EACH:
                    result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ARRAY);
                    if (result != SUIT_SUCCESS) {
                        break;
                    }
                    size_t try_index = item->val.uCount;
                    /* store unpacked array items */
                    for (size_t j = 0; j < try_index; j++) {
                        if (cmd_seq->len >= SUIT_MAX_ARRAY_LENGTH) {
                            result = SUIT_NO_MEMORY;
                        }
                        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
                        if (!suit_continue(mode, result)) {
                            break;
                        }
                        if (result == SUIT_SUCCESS) {
                            cmd_seq->commands[cmd_seq->len].label = label;
                            cmd_seq->commands[cmd_seq->len].value.string.len = item->val.string.len;
                            cmd_seq->commands[cmd_seq->len].value.string.ptr = item->val.string.ptr;
                            cmd_seq->len++;
                        }
                        else if (result == SUIT_INVALID_TYPE_OF_ARGUMENT) {
                            if (!suit_qcbor_skip_any(context, item)) {
                                result = SUIT_FATAL_ERROR;
                            }
                        }
                    }
                    break;
                case SUIT_CONDITION_USE_BEFORE:
                case SUIT_CONDITION_ABORT:
                case SUIT_CONDITION_DEVICE_IDENTIFIER:
                case SUIT_CONDITION_IMAGE_NOT_MATCH:
                case SUIT_CONDITION_MINIMUM_BATTERY:
                case SUIT_CONDITION_UPDATE_AUTHORIZED:
                case SUIT_CONDITION_VERSION:
                case SUIT_DIRECTIVE_DO_EACH:
                case SUIT_DIRECTIVE_MAP_FILTER:
                case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
                case SUIT_DIRECTIVE_WAIT:
                case SUIT_DIRECTIVE_FETCH_URI_LIST:
                case SUIT_DIRECTIVE_SWAP:
                case SUIT_DIRECTIVE_RUN_SEQUENCE:
                default:
                    // TODO
                    suit_debug_print(context, item, "suit_set_directive_or_condition", QCBOR_TYPE_ANY);
                    result = SUIT_NOT_IMPLEMENTED;
            }
            if (!suit_continue(mode, result)) {
                break;
            }
        }
    }
    if (result != SUIT_SUCCESS && !(mode & SUIT_DECODE_MODE_PRESERVE_ON_ERROR)) {
        cmd_seq->len = 0;
    }
    return result;
}

int32_t suit_set_common_sequence_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_command_sequence_t *cmn_seq) {
    return suit_set_command_common_sequence_from_item(mode, context, item, next, cmn_seq, true);
}

int32_t suit_set_common_sequence(uint8_t mode, const suit_buf_t *buf, suit_command_sequence_t *cmn_seq) {
    QCBORDecodeContext cmn_seq_context;
    QCBORItem item;
    QCBORDecode_Init(&cmn_seq_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_common_sequence_from_item(mode, &cmn_seq_context, &item, true, cmn_seq);
    QCBORError error = QCBORDecode_Finish(&cmn_seq_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_common_sequence_from_bstr(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_command_sequence_t *cmn_seq) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    suit_buf_t buf;
    buf.len = item->val.string.len;
    buf.ptr = item->val.string.ptr;
    return suit_set_command_sequence(mode, &buf, cmn_seq);
}

int32_t suit_set_command_sequence_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_command_sequence_t *cmd_seq) {
    return suit_set_command_common_sequence_from_item(mode, context, item, next, cmd_seq, false);
}

int32_t suit_set_command_sequence(uint8_t mode, const suit_buf_t *buf, suit_command_sequence_t *cmd_seq) {
    QCBORDecodeContext cmd_seq_context;
    QCBORItem item;
    QCBORDecode_Init(&cmd_seq_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_command_sequence_from_item(mode, &cmd_seq_context, &item, true, cmd_seq);
    QCBORError error = QCBORDecode_Finish(&cmd_seq_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_command_sequence_from_bstr(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_command_sequence_t *cmd_seq) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        suit_debug_print(context, item, "suit_set_command_sequence_from_bstr", QCBOR_TYPE_BYTE_STRING);
        return result;
    }
    suit_buf_t buf;
    buf.len = item->val.string.len;
    buf.ptr = item->val.string.ptr;
    return suit_set_command_sequence(mode, &buf, cmd_seq);
}

int32_t suit_set_component_identifiers_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_component_identifier_t *identifier) {
    identifier->len = 0;

    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        suit_debug_print(context, item, "suit_set_component_identifiers", QCBOR_TYPE_ARRAY);
        return result;
    }
    size_t len = item->val.uCount;
    for (size_t j = 0; j < len; j++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
        if (!suit_continue(mode, result)) {
            break;
        }
        if (result == SUIT_SUCCESS) {
            identifier->identifier[identifier->len].ptr = item->val.string.ptr;
            identifier->identifier[identifier->len].len = item->val.string.len;
            identifier->len++;
        }
    }
    if (result != SUIT_SUCCESS && !(mode & SUIT_DECODE_MODE_PRESERVE_ON_ERROR)) {
        identifier->len = 0;
    }
    return result;
}

int32_t suit_set_component_identifiers(uint8_t mode, suit_buf_t *buf, suit_component_identifier_t *identifier) {
    QCBORDecodeContext component_context;
    QCBORItem item;
    QCBORDecode_Init(&component_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_component_identifiers_from_item(mode, &component_context, &item, true, identifier);
    QCBORError error = QCBORDecode_Finish(&component_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_components_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_components_t *components) {
    components->len = 0;

    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t len = item->val.uCount;
    for (size_t i = 0; i < len; i++) {
        result = suit_qcbor_get(context, item, true, QCBOR_TYPE_ARRAY);
        if (!suit_continue(mode, result)) {
            break;
        }
        if (result == SUIT_SUCCESS) {
            result = suit_set_component_identifiers_from_item(mode, context, item, false, &components->comp_id[components->len]);
            if (result == SUIT_SUCCESS) {
                components->len++;
            }
            else if (result == SUIT_INVALID_TYPE_OF_ARGUMENT) {
                if (!suit_qcbor_skip_any(context, item)) {
                    result = SUIT_FATAL_ERROR;
                }
            }
        }
        if (!suit_continue(mode, result)) {
            if (!(mode & SUIT_DECODE_MODE_PRESERVE_ON_ERROR)) {
                components->len = 0;
            }
            break;
        }
    }
    return result;
}

int32_t suit_set_authentication_block(uint8_t mode, suit_buf_t *buf, suit_digest_t *digest, const struct t_cose_key *public_key) {
    UsefulBufC signed_cose = {buf->ptr, buf->len};
    int32_t result;
    cose_tag_key_t cose_tag = suit_judge_cose_tag_from_buf(&signed_cose);

    UsefulBufC returned_payload;
    switch (cose_tag) {
        case COSE_SIGN1_TAGGED:
            result = suit_verify_cose_sign1(&signed_cose, public_key, &returned_payload);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            suit_buf_t payload_buf;
            payload_buf.ptr = returned_payload.ptr;
            payload_buf.len = returned_payload.len;
            result = suit_set_digest(mode, &payload_buf, digest);
            break;
        default:
            result = SUIT_NOT_IMPLEMENTED;
    }
    return result;
}

int32_t suit_set_common_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_common_t *common) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            break;
        }
        switch (item->label.uint64) {
            case SUIT_COMPONENTS:
                result = suit_set_components_from_item(mode, context, item, false, &common->components);
                break;
            case SUIT_COMMON_SEQUENCE:
                result = suit_set_common_sequence_from_bstr(mode, context, item, false, &common->cmd_seq);
                break;
            case SUIT_DEPENDENCIES:
            default:
                // TODO
                suit_debug_print(context, item, "suit_set_dependencies(skipping)", QCBOR_TYPE_ARRAY);
                result = SUIT_NOT_IMPLEMENTED;
                if (!suit_qcbor_skip_any(context, item)) {
                    result = SUIT_NO_MORE_ITEMS;
                }
                break;
        }
        if (!suit_continue(mode, result)) {
            break;
        }
    }

    return result;
}

int32_t suit_set_common_from_bstr(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_common_t *common) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBORDecodeContext common_context;
    QCBORDecode_Init(&common_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);
    result = suit_set_common_from_item(mode, &common_context, item, true, common);
    QCBORError error = QCBORDecode_Finish(&common_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_text_component_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_text_component_t *text_component) {
    /* NOTE: in QCBOR_DECODE_MODE_MAP_AS_ARRAY */
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP_AS_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i * 2 < map_count; i++) {
        int32_t result = suit_qcbor_get_next_uint(context, item);
        if (!suit_continue(mode, result)) {
            break;
        }
        if (result == SUIT_SUCCESS) {
            suit_buf_t *buf = NULL;
            switch (item->val.uint64) {
                case SUIT_TEXT_VENDOR_NAME:
                    buf = &text_component->vendor_name;
                    break;
                case SUIT_TEXT_MODEL_NAME:
                    buf = &text_component->model_name;
                    break;
                case SUIT_TEXT_VENDOR_DOMAIN:
                    buf = &text_component->vendor_domain;
                    break;
                case SUIT_TEXT_MODEL_INFO:
                    buf = &text_component->model_info;
                    break;
                case SUIT_TEXT_COMPONENT_DESCRIPTION:
                    buf = &text_component->component_description;
                    break;
                case SUIT_TEXT_COMPONENT_VERSION:
                    buf = &text_component->component_version;
                    break;
                case SUIT_TEXT_VERSION_REQUIRED:
                    buf = &text_component->version_required;
                    break;
            }
            if (buf != NULL) {
                result = suit_qcbor_get_next(context, item, QCBOR_TYPE_TEXT_STRING);
                if (!suit_continue(mode, result)) {
                    break;
                }
                if (result == SUIT_SUCCESS) {
                    buf->len = item->val.string.len;
                    buf->ptr = item->val.string.ptr;
                }
                else if (result == SUIT_INVALID_TYPE_OF_ARGUMENT) {
                    if (!suit_qcbor_skip_any(context, item)) {
                        result = SUIT_FATAL_ERROR;
                    }
                }
            }
            else {
                result = SUIT_NOT_IMPLEMENTED;
                if (!suit_continue(mode, result)) {
                    break;
                }
            }
        }
        else {
            result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
            if (result != SUIT_SUCCESS) {
                result = SUIT_FATAL_ERROR;
            }
            else {
                if (!suit_qcbor_skip_any(context, item)) {
                    result = SUIT_FATAL_ERROR;
                }
            }
        }
        if (!suit_continue(mode, result)) {
            break;
        }
    }
    return result;
}

int32_t suit_set_text_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_text_t *text) {
    /* NOTE: in QCBOR_DECODE_MODE_MAP_AS_ARRAY */
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP_AS_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    size_t map_count = item->val.uCount;
    text->component_len = 0;
    for (size_t i = 0; i * 2 < map_count; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            break;
        }

        switch (item->uDataType) {
            case QCBOR_TYPE_ARRAY:
                result = suit_set_component_identifiers_from_item(mode, context, item, false, &text->component[text->component_len].key);
                if (result != SUIT_SUCCESS) {
                    if (!suit_qcbor_skip_any(context, item)) {
                        result = SUIT_FATAL_ERROR;
                    }
                    break;
                }
                result = suit_set_text_component_from_item(mode, context, item, true, &text->component[text->component_len].text_component);
                if (result == SUIT_SUCCESS) {
                    text->component_len++;
                }
                else if (result == SUIT_INVALID_TYPE_OF_ARGUMENT) {
                    if (!suit_qcbor_skip_any(context, item)) {
                        result = SUIT_FATAL_ERROR;
                    }
                }
                break;
            case QCBOR_TYPE_INT64:
            case QCBOR_TYPE_UINT64:
                switch (item->val.int64) {
                    case SUIT_TEXT_MANIFEST_DESCRIPTION:
                        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_TEXT_STRING);
                        if (result == SUIT_SUCCESS) {
                            text->manifest_description.ptr = item->val.string.ptr;
                            text->manifest_description.len = item->val.string.len;
                        }
                        break;
                    case SUIT_TEXT_UPDATE_DESCRIPTION:
                    case SUIT_TEXT_MANIFEST_JSON_SOURCE:
                    case SUIT_TEXT_MANIFEST_YAML_SOURCE:
                    default:
                        suit_debug_print(context, item, "suit_set_text", QCBOR_TYPE_INT64);
                        result = SUIT_NOT_IMPLEMENTED;
                        if (!suit_continue(mode, result)) {
                            if (!suit_qcbor_skip_any(context, item)) {
                                result = SUIT_FATAL_ERROR;
                            }
                        }
                        break;
                }
                break;
            default:
                result = SUIT_NOT_IMPLEMENTED;
        }
        if (!suit_continue(mode, result)) {
            break;
        }
    }
    if (result != SUIT_SUCCESS && !(mode & SUIT_DECODE_MODE_PRESERVE_ON_ERROR)) {
        text->component_len = 0;
    }
    return result;
}

int32_t suit_set_text_from_bstr(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_text_t *text) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    QCBORDecodeContext text_context;
    /* NOTE: SUIT_Text_Map may contain component-identifier key,
             so we parse as QCBOR_DECODE_MODE_MAP_AS_ARRAY
             to prevent invalid CBOR Map */
    QCBORDecode_Init(&text_context,
                     (UsefulBufC){item->val.string.ptr, item->val.string.len},
                     QCBOR_DECODE_MODE_MAP_AS_ARRAY);
    result = suit_set_text_from_item(mode, &text_context, item, true, text);
    QCBORError error = QCBORDecode_Finish(&text_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_verify_digest(suit_buf_t *buf, suit_digest_t *digest) {
    int32_t result;

    switch (digest->algorithm_id) {
        case SUIT_ALGORITHM_ID_SHA256:
            result = suit_verify_sha256(buf->ptr, buf->len, digest->bytes.ptr, digest->bytes.len);
            break;
        case SUIT_ALGORITHM_ID_SHA224:
        case SUIT_ALGORITHM_ID_SHA384:
        case SUIT_ALGORITHM_ID_SHA512:
        case SUIT_ALGORITHM_ID_SHA3_224:
        case SUIT_ALGORITHM_ID_SHA3_256:
        case SUIT_ALGORITHM_ID_SHA3_384:
        case SUIT_ALGORITHM_ID_SHA3_512:
        default:
            result = SUIT_NOT_IMPLEMENTED;
    }
    return result;
}

int32_t suit_verify_item(QCBORDecodeContext *context, QCBORItem *item, suit_digest_t *digest, bool suit_install) {
    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    if (digest->bytes.ptr == NULL) {
        return SUIT_FAILED_TO_VERIFY;
    }
    suit_buf_t buf;
    size_t cursor = UsefulInputBuf_Tell(&context->InBuf);
    buf.len = suit_qcbor_calc_rollback(item);
    buf.len -= (suit_install) ? 0 : (buf.len - item->val.string.len);
    buf.ptr = (uint8_t *)context->InBuf.UB.ptr + (cursor - buf.len);
    return suit_verify_digest(&buf, digest);
}

int32_t suit_set_manifest_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_manifest_t *manifest) {
    manifest->sev_man_mem.dependency_resolution_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.payload_fetch_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.text_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.coswid_status = SUIT_SEVERABLE_INVALID;

    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            break;
        }
        int64_t label = item->label.int64;
        switch (label) {
            case SUIT_MANIFEST_VERSION:
                if (item->uDataType != QCBOR_TYPE_INT64) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                manifest->version = (uint32_t) item->val.uint64;
                break;
            case SUIT_MANIFEST_SEQUENCE_NUMBER:
                if (item->uDataType != QCBOR_TYPE_INT64) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                manifest->sequence_number = (uint32_t) item->val.uint64;
                break;
            case SUIT_COMMON:
                result = suit_set_common_from_bstr(mode, context, item, false, &manifest->common);
                break;
            case SUIT_PAYLOAD_FETCH:
                if (item->uDataType == QCBOR_TYPE_ARRAY) {
                    /* SUIT_Digest */
                    result = suit_set_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.payload_fetch);
                }
                else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                    result = suit_set_command_sequence_from_bstr(mode, context, item, false, &manifest->sev_man_mem.payload_fetch);
                    if (result == SUIT_SUCCESS) {
                        manifest->sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IN_MANIFEST;
                        if (manifest->is_verified) {
                            manifest->sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IS_VERIFIED;
                        }
                    }
                }
                else {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                break;
            case SUIT_INSTALL:
                if (item->uDataType == QCBOR_TYPE_ARRAY) {
                    /* SUIT_Digest */
                    result = suit_set_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.install);
                }
                else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                    /* bstr .cbor SUIT_Command_Sequence */
                    result = suit_set_command_sequence_from_bstr(mode, context, item, false, &manifest->sev_man_mem.install);
                    if (result == SUIT_SUCCESS) {
                        manifest->sev_man_mem.install_status |= SUIT_SEVERABLE_IN_MANIFEST;
                        if (manifest->is_verified) {
                            manifest->sev_man_mem.install_status |= SUIT_SEVERABLE_IS_VERIFIED;
                        }
                    }
                }
                else {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                break;
            case SUIT_TEXT:
                if (item->uDataType == QCBOR_TYPE_ARRAY) {
                    /* SUIT_Digest */
                    result = suit_set_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.text);
                }
                else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                    /* bstr .cbor SUIT_Text_Map */
                    result = suit_set_text_from_bstr(mode, context, item, false, &manifest->sev_man_mem.text);
                    if (result == SUIT_SUCCESS) {
                        manifest->sev_man_mem.text_status |= SUIT_SEVERABLE_IN_MANIFEST;
                        if (manifest->is_verified) {
                            manifest->sev_man_mem.text_status |= SUIT_SEVERABLE_IS_VERIFIED;
                        }
                    }
                }
                else {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                break;
            case SUIT_COSWID:
                if (item->uDataType == QCBOR_TYPE_ARRAY) {
                    /* SUIT_Digest */
                    result = suit_set_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.coswid);
                }
                else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                    /* bstr .cbor concise-software-identity */
                    manifest->sev_man_mem.coswid.ptr = item->val.string.ptr;
                    manifest->sev_man_mem.coswid.len = item->val.string.len;
                    result = SUIT_SUCCESS;
                }
                else {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                break;
            /* SUIT_Unseverabme_Members */
            case SUIT_VALIDATE:
                result = suit_set_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.validate);
                break;
            case SUIT_LOAD:
                result = suit_set_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.load);
                break;
            case SUIT_RUN:
                result = suit_set_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.run);
                break;
            case SUIT_REFERENCE_URI:
            case SUIT_DEPENDENCY_RESOLUTION:
            default:
                // TODO
                result = SUIT_NOT_IMPLEMENTED;
                if (suit_continue(mode, result)) {
                    if (!suit_qcbor_skip_any(context, item)) {
                        result = SUIT_FATAL_ERROR;
                    }
                }
                break;
        }
        if (!suit_continue(mode, result)) {
            break;
        }
    }
    return result;
}

int32_t suit_set_manifest(uint8_t mode, suit_buf_t *buf, suit_manifest_t *manifest) {
    QCBORDecodeContext manifest_context;
    QCBORItem item;
    QCBORDecode_Init(&manifest_context,
                     (UsefulBufC){buf->ptr, buf->len},
                     QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_manifest_from_item(mode, &manifest_context, &item, true, manifest);
    QCBORError error = QCBORDecode_Finish(&manifest_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_manifest_from_bstr(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_manifest_t *manifest, suit_digest_t *digest) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* verify the SUIT_Manifest with SUIT_Digest */
    result = suit_verify_item(context, item, digest, true);
    if (!suit_continue(mode, result)) {
        return result;
    }
    if (result == SUIT_SUCCESS) {
        manifest->is_verified = true;
    }
    suit_buf_t buf = {.ptr = item->val.string.ptr, .len = item->val.string.len};

    return suit_set_manifest(mode, &buf, manifest);
}

int32_t suit_set_authentication_wrapper_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_authentication_wrapper_t *wrapper, const struct t_cose_key *public_key) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    if (item->val.uCount >= SUIT_MAX_ARRAY_LENGTH) {
        return SUIT_NO_MEMORY;
    }

    size_t len = item->val.uCount;
    wrapper->len = 0;
    for (size_t i = 0; i < len; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
        if (!suit_continue(mode, result)) {
            break;
        }
        suit_buf_t buf;
        buf.ptr = item->val.string.ptr;
        buf.len = item->val.string.len;

        if (i == 0) {
            result = suit_set_digest(mode, &buf, &wrapper->digest[0]);
        }
        else {
            result = suit_set_authentication_block(mode, &buf, &wrapper->digest[wrapper->len], public_key);
        }
        if (!suit_continue(mode, result)) {
            break;
        }
        wrapper->len++;
    }
    if (result != SUIT_SUCCESS && !(mode & SUIT_DECODE_MODE_PRESERVE_ON_ERROR)) {
        wrapper->len = 0;
    }

    return result;
}

int32_t suit_set_authentication_wrapper(uint8_t mode, suit_buf_t *buf, suit_authentication_wrapper_t *wrapper, const struct t_cose_key *public_key) {
    QCBORDecodeContext auth_context;
    QCBORItem item;
    QCBORDecode_Init(&auth_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_authentication_wrapper_from_item(mode, &auth_context, &item, true, wrapper, public_key);
    QCBORError error = QCBORDecode_Finish(&auth_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

int32_t suit_set_envelope_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_envelope_t *envelope, const struct t_cose_key *public_key) {
    int32_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    size_t map_count = item->val.uCount;
    bool is_authentication_set = false;
    bool is_manifest_set = false;
    suit_buf_t buf;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            return result;
        }
        switch (item->label.uint64) {
            case SUIT_AUTHENTICATION:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                buf.ptr = item->val.string.ptr;
                buf.len = item->val.string.len;
                result = suit_set_authentication_wrapper(mode, &buf, &envelope->wrapper, public_key);
                if (result == SUIT_SUCCESS) {
                    is_authentication_set = true;
                }
                break;
            case SUIT_MANIFEST:
                if (!is_authentication_set && !suit_continue(mode, SUIT_FAILED_TO_VERIFY)) {
                     result = SUIT_FAILED_TO_VERIFY;
                     break;
                }
                result = suit_set_manifest_from_bstr(mode, context, item, false, &envelope->manifest, &envelope->wrapper.digest[envelope->wrapper.len - 1]);
                if (!suit_continue(mode, result)) {
                    break;
                }
                if (result == SUIT_SUCCESS || result == SUIT_FAILED_TO_VERIFY) {
                    is_manifest_set = true;
                }
                break;
            /* SUIT_Severable_Manifest_members */
            case SUIT_PAYLOAD_FETCH:
                if (!is_authentication_set || !is_manifest_set) {
                    result = SUIT_FAILED_TO_VERIFY;
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                }
                result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.payload_fetch, true);
                if (!suit_continue(mode, result)) {
                    break;
                }
                else if (is_authentication_set && result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
                result = suit_set_command_sequence_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.payload_fetch);
                if (result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                break;
            case SUIT_INSTALL:
                if (!is_authentication_set || !is_manifest_set) {
                    result = SUIT_FAILED_TO_VERIFY;
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                }
                result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.install, true);
                if (!suit_continue(mode, result)) {
                    break;
                }
                else if (is_authentication_set && result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.install_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
                result = suit_set_command_sequence_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.install);
                if (result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.install_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                break;
            case SUIT_TEXT:
                if (!is_authentication_set || !is_manifest_set) {
                    result = SUIT_FAILED_TO_VERIFY;
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                }
                result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.text, false);
                if (!suit_continue(mode, result)) {
                    break;
                }
                else if (is_authentication_set && result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.text_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
                result = suit_set_text_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.text);
                if (result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.text_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                break;
            case SUIT_COSWID:
                if (!is_authentication_set || !is_manifest_set) {
                    result = SUIT_FAILED_TO_VERIFY;
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                }
                result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.coswid, true);
                if (!suit_continue(mode, result)) {
                    break;
                }
                else if (is_authentication_set && result == SUIT_SUCCESS) {
                    envelope->manifest.sev_man_mem.coswid_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                envelope->manifest.sev_man_mem.coswid.ptr = item->val.string.ptr;
                envelope->manifest.sev_man_mem.coswid.len = item->val.string.len;
                break;
            case SUIT_DELEGATION:
            case SUIT_DEPENDENCY_RESOLUTION:
            default:
                // TODO
                result = SUIT_NOT_IMPLEMENTED;
                if (!suit_qcbor_skip_any(context, item)) {
                    result = SUIT_NO_MORE_ITEMS;
                }
        }
        if (!suit_continue(mode, result)) {
            break;
        }
    }

    return result;
}

int32_t suit_set_envelope(uint8_t mode, suit_buf_t *buf, suit_envelope_t *envelope, const struct t_cose_key *public_key) {
    QCBORDecodeContext decode_context;
    QCBORItem item;
    QCBORDecode_Init(&decode_context,
                     (UsefulBufC){buf->ptr, buf->len},
                     QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_envelope_from_item(mode, &decode_context, &item, true, envelope, public_key);
    QCBORError error = QCBORDecode_Finish(&decode_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}
