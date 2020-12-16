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

bool suit_qcbor_get_next(QCBORDecodeContext *message,
                    QCBORItem *item,
                    QCBORError *error,
                    uint8_t data_type) {
    if ((*error = QCBORDecode_GetNext(message, item))) {
        suit_debug_print(message, item, error, "suit_qcbor_get_next", QCBOR_TYPE_ANY);
        return false;
    }
    if (data_type != QCBOR_TYPE_ANY && item->uDataType != data_type) {
        suit_debug_print(message, item, error, "suit_qcbor_get_next", data_type);
        return false;
    }
    return true;
}

bool suit_qcbor_get_next_uint(QCBORDecodeContext *message,
                         QCBORItem *item,
                         QCBORError *error) {
    if (!suit_qcbor_get_next(message, item, error, QCBOR_TYPE_ANY)) {
        suit_debug_print(message, item, error, "suit_qcbor_get_next_uint", QCBOR_TYPE_UINT64);
        return false;
    }
    if (item->uDataType == QCBOR_TYPE_INT64) {
        if (item->val.int64 < 0) {
            return false;
        }
    }
    else if (item->uDataType != QCBOR_TYPE_UINT64) {
        return false;
    }
    return true;
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

size_t suit_qcbor_calc_rollback(QCBORItem *item) {
    uint8_t type = item->uDataType;
    if (item->uDataType == QCBOR_TYPE_INT64 && suit_qcbor_value_is_uint64(item)) {
        type = QCBOR_TYPE_UINT64;
    }

    switch (type) {
        case QCBOR_TYPE_UINT64:
            if (item->val.uint64 < 23) {
                return 1;
            }
            else if (item->val.uint64 < UINT8_MAX) {
                return 2;
            }
            else if (item->val.uint64 < UINT16_MAX) {
                return 3;
            }
            else if (item->val.uint64 < UINT32_MAX) {
                return 4;
            }
            return 5;
        case QCBOR_TYPE_INT64:
            if (item->val.int64 > -25) {
                return 1;
            }
            else if (item->val.int64 > -1 - UINT8_MAX) {
                return 2;
            }
            else if (item->val.int64 > -1 - UINT16_MAX) {
                return 3;
            }
            else if (item->val.int64 > -1 - UINT32_MAX) {
                return 4;
            }
            return 5;
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TEXT_STRING:
            if (item->val.string.len < 24) {
                return 1;
            }
            else if (item->val.string.len < UINT8_MAX) {
                return 2;
            }
            else if (item->val.string.len < UINT16_MAX) {
                return 3;
            }
            else if (item->val.string.len < UINT32_MAX) {
                return 4;
            }
            return 5;
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
                return 4;
            }
            return 5;
    }
    return 0;
}

bool suit_qcbor_skip_any(QCBORDecodeContext *message,
                    QCBORItem *item,
                    QCBORError *error);

bool suit_qcbor_skip_array_and_map(QCBORDecodeContext *message,
                            QCBORItem *item,
                            QCBORError *error) {
    if (item->uDataType != QCBOR_TYPE_ARRAY && item->uDataType != QCBOR_TYPE_MAP) {
        return false;
    }
    size_t array_size = item->val.uCount;
    for (size_t i = 0; i < array_size; i++) {
        if (!suit_qcbor_get_next(message, item, error, QCBOR_TYPE_ANY)) {
            return false;
        }
        if (!suit_qcbor_skip_any(message, item, error)) {
            return false;
        }
    }
    return true;
}

bool suit_qcbor_skip_any(QCBORDecodeContext *message,
                    QCBORItem *item,
                    QCBORError *error) {
    switch (item->uDataType) {
        case QCBOR_TYPE_ARRAY:
        case QCBOR_TYPE_MAP:
            if (!suit_qcbor_skip_array_and_map(message, item, error)) {
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

int32_t suit_set_digest(QCBORDecodeContext *context,
                        QCBORItem *item,
                        QCBORError *error,
                        bool next,
                        suit_digest_t *digest) {
    digest->algorithm_id = SUIT_ALGORITHM_ID_INVALID;
    digest->bytes.len = 0;
    //digest->extension.len = 0;
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_ARRAY) {
        suit_debug_print(context, item, error, "suit_set_digest", QCBOR_TYPE_ARRAY);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    size_t ext_len = (item->val.uCount > 2) ? item->val.uCount - 2 : 0;

    if (!suit_qcbor_get_next_uint(context, item, error)) {
        suit_debug_print(context, item, error, "suit_set_digest@algorithm-id", QCBOR_TYPE_INT64);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    digest->algorithm_id = item->val.uint64;

    if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        suit_debug_print(context, item, error, "suit_set_digest@digest-bytes", QCBOR_TYPE_BYTE_STRING);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    digest->bytes.ptr = item->val.string.ptr;
    digest->bytes.len = item->val.string.len;

    for (size_t i = 0; i < ext_len; i++) {
        // TODO
        suit_debug_print(context, item, error, "suit_set_digest skipping SUIT_Digest-extensions", QCBOR_TYPE_ANY);
        suit_qcbor_skip_any(context, item, error);
    }
    return SUIT_SUCCESS;
}

int32_t suit_set_digest_from_buf(suit_buf_t *buf,
                                 suit_digest_t *digest) {
    QCBORDecodeContext digest_context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&digest_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_digest(&digest_context, &item, &error, true, digest);
    QCBORDecode_Finish(&digest_context);
    return result;
}

int32_t suit_set_digest_from_bytes(QCBORDecodeContext *context,
                                   QCBORItem *item,
                                   QCBORError *error,
                                   bool next,
                                   suit_digest_t *digest) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        suit_debug_print(context, item, error, "suit_set_digest_from_bytes", QCBOR_TYPE_BYTE_STRING);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    suit_buf_t buf;
    buf.ptr = item->val.string.ptr;
    buf.len = item->val.string.len;
    return suit_set_digest_from_buf(&buf, digest);
}

int32_t suit_set_parameters_list(QCBORDecodeContext *context,
                                 QCBORItem *item,
                                 QCBORError *error,
                                 bool next,
                                 suit_parameters_list_t *params_list) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_MAP) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }

    params_list->len = item->val.uCount;
    // printf("suit_set_parameters_list : len = %lu\n", params_list->len);
    int32_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_UNEXPECTED_ERROR;
        }
        params_list->params[i].label = item->label.uint64;
        switch (params_list->params[i].label) {
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    printf("\nsuit_set_parameters_list : Error! uDataType = %d\n", item->uDataType);
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                params_list->params[i].value.string.ptr = item->val.string.ptr;
                params_list->params[i].value.string.len = item->val.string.len;
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                result = suit_set_digest_from_bytes(context, item, error, false, &params_list->params[i].value.digest);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_PARAMETER_COMPONENT_OFFSET:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_COMPRESSION_INFO:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                if (!suit_qcbor_value_is_uint64(item)) {
                    suit_debug_print(context, item, error, "suit_set_parameters_list", QCBOR_TYPE_UINT64);
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                params_list->params[i].value.uint64 = item->val.uint64;
                break;
            case SUIT_PARAMETER_URI:
                if (item->uDataType != QCBOR_TYPE_TEXT_STRING) {
                    printf("\nsuit_set_parameters_list : Error! uDataType = %d\n", item->uDataType);
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                params_list->params[i].value.string.ptr = item->val.string.ptr;
                params_list->params[i].value.string.len = item->val.string.len;
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
                printf("suit_set_parameters_list skip %lu\n", item->label.uint64);
                suit_debug_print(context, item, error, "suit_set_parameters_list", QCBOR_TYPE_NONE);
                break;
            default:
                return SUIT_UNEXPECTED_ERROR;
        }
    }
    return result;
}

int32_t suit_set_command_custom(QCBORDecodeContext *context,
                                QCBORItem *item,
                                QCBORError *error,
                                int64_t label,
                                suit_command_sequence_item_t *cmd_item) {
    // TODO:
    printf("suit_set_command_custom is not implemented (label %ld)", label);
    return SUIT_UNEXPECTED_ERROR;
}

bool inline is_suit_command_custom(QCBORItem *item) {
    /* suit-command-custom = nint */
    return !suit_qcbor_value_is_uint64(item);
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

int32_t suit_set_command_common_sequence(
            QCBORDecodeContext *context,
            QCBORItem *item,
            QCBORError *error,
            bool next,
            suit_command_sequence_t *cmd_seq,
            bool is_common_sequence) {
    /* NOTE:
     * SUIT_Common_Sequence  = [ + (SUIT_Condition // SUIT_Common_Commands) ]
     * SUIT_Command_Sequence = [ + (SUIT_Condition // SUIT_Directive // SUIT_Command_Custom ] */
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_ARRAY) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    int32_t result = SUIT_SUCCESS;
    const uint16_t array_count = item->val.uCount;
    // printf("suit_set_command_sequence : array_count = %u\n", array_count);
    cmd_seq->len = 0;
    size_t commands_index = 0;
    size_t try_index;
    for (size_t i = 0; i < array_count; i += 2) {
        if (commands_index >= SUIT_MAX_ARRAY_LENGTH) {
            return SUIT_NO_MEMORY;
        }
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_INT64)) {
            return SUIT_UNEXPECTED_ERROR;
        }
        int64_t label = item->val.int64;
        // NOTE: assert every label is in [INT64_MIN, INT64_MAX]
        if (label < 0) {
            /* SUIT_Command_Custom */
            result = suit_set_command_custom(
                    context, item, error, label,
                    &cmd_seq->commands[commands_index]);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        else {
            /* SUIT_Condition // SUIT_Directive */
            if (is_common_sequence && is_suit_directive_only(label)) {
                /* SUIT_Command_Custom should not come, so skip them */
                printf("suit_set_common_sequence skip label %ld\n", label);
                return SUIT_UNEXPECTED_ERROR;
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
                    if (!suit_qcbor_get_next_uint(context, item, error)) {
                        suit_debug_print(context, item, error, "suit_set_directive_or_condition", QCBOR_TYPE_UINT64);
                        return SUIT_INVALID_TYPE_OF_ARGUMENT;
                    }
                    cmd_seq->commands[commands_index].label = label;
                    cmd_seq->commands[commands_index].value.uint64 = item->val.uint64;
                    commands_index++;
                    break;
                case SUIT_DIRECTIVE_SET_PARAMETERS:
                case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                    result = suit_set_parameters_list(context, item, error, true, &cmd_seq->commands[commands_index].value.params_list);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    cmd_seq->commands[commands_index].label = label;
                    commands_index++;
                    break;
                case SUIT_DIRECTIVE_TRY_EACH:
                    if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
                        return SUIT_INVALID_TYPE_OF_ARGUMENT;
                    }
                    try_index = item->val.uCount;
                    /* store unpacked array items */
                    for (size_t j = 0; j < try_index; j++) {
                        if (commands_index >= SUIT_MAX_ARRAY_LENGTH) {
                            return SUIT_NO_MEMORY;
                        }
                        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
                            return SUIT_INVALID_TYPE_OF_ARGUMENT;
                        }
                        cmd_seq->commands[commands_index].label = label;
                        cmd_seq->commands[commands_index].value.string.len = item->val.string.len;
                        cmd_seq->commands[commands_index].value.string.ptr = item->val.string.ptr;
                        commands_index++;
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
                    printf("suit_set_directive_or_condition skip label %ld\n", label);
                    suit_debug_print(context, item, error,
                                     "suit_set_directive_or_condition",
                                     QCBOR_TYPE_ANY);
                    return SUIT_UNEXPECTED_ERROR;
            }
        }
    }
    cmd_seq->len = commands_index;
    return SUIT_SUCCESS;
}

int32_t suit_set_common_sequence(QCBORDecodeContext *context,
                                 QCBORItem *item,
                                 QCBORError *error,
                                 bool next,
                                 suit_command_sequence_t *cmn_seq) {
    return suit_set_command_common_sequence(context, item, error, next, cmn_seq, true);
}

int32_t suit_set_common_sequence_from_buf(const suit_buf_t *buf, suit_command_sequence_t *cmn_seq) {
    QCBORDecodeContext cmn_seq_context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&cmn_seq_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_common_sequence(&cmn_seq_context, &item, &error, true, cmn_seq);
    QCBORDecode_Finish(&cmn_seq_context);
    return result;
}

int32_t suit_set_common_sequence_from_bytes(QCBORDecodeContext *context,
                                            QCBORItem *item,
                                            QCBORError *error,
                                            bool next,
                                            suit_command_sequence_t *cmn_seq) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("\nsuit_set_command_sequence_from_bytes : Error! uDataType = %d\n", item->uDataType);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    suit_buf_t buf;
    buf.len = item->val.string.len;
    buf.ptr = item->val.string.ptr;
    return suit_set_command_sequence_from_buf(&buf, cmn_seq);
}


int32_t suit_set_command_sequence(QCBORDecodeContext *context,
                         QCBORItem *item,
                         QCBORError *error,
                         bool next,
                         suit_command_sequence_t *cmd_seq) {
    return suit_set_command_common_sequence(context, item, error, next, cmd_seq, false);
}

int32_t suit_set_command_sequence_from_buf(const suit_buf_t *buf, suit_command_sequence_t *cmd_seq) {
    QCBORDecodeContext cmd_seq_context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&cmd_seq_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_command_sequence(&cmd_seq_context, &item, &error, true, cmd_seq);
    QCBORDecode_Finish(&cmd_seq_context);
    return result;
}

int32_t suit_set_command_sequence_from_bytes(QCBORDecodeContext *context,
                                            QCBORItem *item,
                                            QCBORError *error,
                                            bool next,
                                            suit_command_sequence_t *cmd_seq) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        suit_debug_print(context, item, error, "suit_set_command_sequence_from_bytes", QCBOR_TYPE_BYTE_STRING);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    suit_buf_t buf;
    buf.len = item->val.string.len;
    buf.ptr = item->val.string.ptr;
    return suit_set_command_sequence_from_buf(&buf, cmd_seq);
}

int32_t suit_set_sev_cmd_seq_from_bytes(QCBORDecodeContext *context,
                                                QCBORItem *item,
                                                QCBORError *error,
                                                bool next,
                                                suit_sev_command_sequence_t *sev_cmd_seq) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        suit_debug_print(context, item, error, "suit_set_sev_cmd_seq_from_bytes", QCBOR_TYPE_BYTE_STRING);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
   }
    QCBORDecodeContext sev_cmd_seq_context;
    QCBORDecode_Init(&sev_cmd_seq_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);

    // TODO : Check SUIT_Digest
    int32_t result = suit_set_command_sequence(
                        &sev_cmd_seq_context, item, error, true,
                        &sev_cmd_seq->value.cmd_seq);
    QCBORDecode_Finish(&sev_cmd_seq_context);
    return result;
}

int32_t suit_set_component_identifiers(QCBORDecodeContext *context,
                                       QCBORItem *item,
                                       QCBORError *error,
                                       bool next,
                                       suit_component_identifier_t *identifier) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_ARRAY) {
        suit_debug_print(context, item, error, "suit_set_component_identifiers", QCBOR_TYPE_ARRAY);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    identifier->len = item->val.uCount;
    for (size_t j = 0; j < identifier->len; j++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
            identifier->len = j;
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        identifier->identifier[j].ptr = item->val.string.ptr;
        identifier->identifier[j].len = item->val.string.len;
    }
    return SUIT_SUCCESS;
}

int32_t suit_set_component_identifiers_from_buf(suit_buf_t *buf,
                                                QCBORItem *item,
                                                QCBORError *error,
                                                suit_component_identifier_t *identifier) {
    QCBORDecodeContext component_context;
    QCBORDecode_Init(&component_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_component_identifiers(&component_context, item, error, true, identifier);
    QCBORDecode_Finish(&component_context);
    return result;
}

int32_t suit_set_components(QCBORDecodeContext *context,
                            QCBORItem *item,
                            QCBORError *error,
                            bool next,
                            suit_components_t *components) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_ARRAY) {
        suit_debug_print(context, item, error, "suit_set_components", QCBOR_TYPE_ARRAY);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    int32_t result = SUIT_SUCCESS;
    components->len = item->val.uCount;
    for (size_t i = 0; i < components->len; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        result = suit_set_component_identifiers(context, item, error, false, &components->comp_id[i]);
        if (result != SUIT_SUCCESS) {
            components->len = i;
            return result;
        }
    }

    return SUIT_SUCCESS;
}

int32_t suit_set_authentication_block_from_buf(suit_buf_t *buf,
                                       suit_digest_t *digest,
                                       const char *public_key) {
    UsefulBufC signed_cose = {buf->ptr, buf->len};
    int32_t result;
    cose_tag_key_t cose_tag = suit_judge_cose_tag_from_buf(&signed_cose);

    UsefulBufC returned_payload;
    switch (cose_tag) {
        case COSE_SIGN1_TAGGED:
            result = suit_verify_cose_sign1(&signed_cose, public_key, &returned_payload);
            if (result != SUIT_SUCCESS) {
                printf("failed to verify COSE_SIGN1\n");
                return result;
            }
            suit_buf_t payload_buf;
            payload_buf.ptr = returned_payload.ptr;
            payload_buf.len = returned_payload.len;
            result = suit_set_digest_from_buf(&payload_buf, digest);
            break;
        default:
            printf("WARNING: SKIPPING VERIFICATION of SUIT_Authentication_Block in suit_set_digest\n");
            result = SUIT_UNEXPECTED_ERROR;
    }

    return result;
}

int32_t suit_set_common(QCBORDecodeContext *context,
                        QCBORItem *item,
                        QCBORError *error,
                        bool next,
                        suit_common_t *common) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    QCBORDecodeContext common_context;
    QCBORDecode_Init(&common_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);

    if (!suit_qcbor_get_next(&common_context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    int32_t result = SUIT_SUCCESS;
    uint16_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        if (!suit_qcbor_get_next(&common_context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        switch (item->label.uint64) {
            case SUIT_DEPENDENCIES:
                // TODO
                suit_debug_print(&common_context, item, error,
                                 "suit_set_dependencies(skipping)",
                                 QCBOR_TYPE_ARRAY);
                suit_qcbor_skip_any(&common_context, item, error);
                break;
            case SUIT_COMPONENTS:
                result = suit_set_components(&common_context, item, error, false, &common->components);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_COMMON_SEQUENCE:
                result = suit_set_common_sequence_from_bytes(&common_context,
                                                             item,
                                                             error,
                                                             false,
                                                             &common->cmd_seq);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            default:
                break;
        }
    }

    QCBORDecode_Finish(&common_context);
    return SUIT_SUCCESS;
}

int32_t suit_set_text_component(QCBORDecodeContext *context,
                              QCBORItem *item,
                              QCBORError *error,
                              bool next,
                              suit_text_component_t *text_component) {
    /* NOTE: in QCBOR_DECODE_MODE_MAP_AS_ARRAY */
    int32_t result = SUIT_SUCCESS;
    if (next) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_MAP_AS_ARRAY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
    }
    else {
        if (item->uDataType != QCBOR_TYPE_MAP_AS_ARRAY) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i * 2 < map_count; i++) {
        if (!suit_qcbor_get_next_uint(context, item, error)) {
            return SUIT_UNEXPECTED_ERROR;
        }
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
            default:
                return SUIT_UNEXPECTED_ERROR;
        }
        if (buf != NULL) {
            if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_TEXT_STRING)) {
                return SUIT_INVALID_TYPE_OF_ARGUMENT;
            }
            buf->len = item->val.string.len;
            buf->ptr = item->val.string.ptr;
        }
        else {
            return SUIT_UNEXPECTED_ERROR;
        }
    }
    return result;
}

int32_t suit_set_text(QCBORDecodeContext *context,
                      QCBORItem *item,
                      QCBORError *error,
                      bool next,
                      suit_text_t *text) {
    /* NOTE: in QCBOR_DECODE_MODE_MAP_AS_ARRAY */
    if (next) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_MAP_AS_ARRAY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
    }
    else {
        if (item->uDataType != QCBOR_TYPE_MAP_AS_ARRAY) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
    }

    int32_t result = SUIT_SUCCESS;
    size_t map_count = item->val.uCount;
    text->component_len = 0;
    for (size_t i = 0; i * 2 < map_count; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_UNEXPECTED_ERROR;
        }
        switch (item->uDataType) {
            case QCBOR_TYPE_ARRAY:
                result = suit_set_component_identifiers(context, item, error, false, &text->component[text->component_len].key);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                result = suit_set_text_component(context, item, error, true, &text->component[text->component_len].text_component);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                text->component_len++;
                break;
            case QCBOR_TYPE_INT64:
            case QCBOR_TYPE_UINT64:
                switch (item->val.int64) {
                    case SUIT_TEXT_MANIFEST_DESCRIPTION:
                        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_TEXT_STRING)) {
                            return SUIT_INVALID_TYPE_OF_ARGUMENT;
                        }
                        text->manifest_description.ptr = item->val.string.ptr;
                        text->manifest_description.len = item->val.string.len;
                        break;
                    case SUIT_TEXT_UPDATE_DESCRIPTION:
                    case SUIT_TEXT_MANIFEST_JSON_SOURCE:
                    case SUIT_TEXT_MANIFEST_YAML_SOURCE:
                        suit_debug_print(context, item, error, "suite_set_text(skipping)", QCBOR_TYPE_ANY);
                        suit_qcbor_skip_any(context, item, error);
                        break;
                    default:
                        suit_debug_print(context, item, error, "suit_set_text(UNEXPECTED)", QCBOR_TYPE_INT64);
                        return SUIT_UNEXPECTED_ERROR;
                }
                break;
            default:
                return SUIT_UNEXPECTED_ERROR;
        }
    }
    return result;
}

int32_t suit_set_text_from_bytes(QCBORDecodeContext *context,
                                 QCBORItem *item,
                                 QCBORError *error,
                                 bool next,
                                 suit_text_t *text) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    QCBORDecodeContext text_context;
    /* NOTE: SUIT_Text_Map may contain component-identifier key,
             so we parse as QCBOR_DECODE_MODE_MAP_AS_ARRAY
             to prevent invalid CBOR Map */
    QCBORDecode_Init(&text_context,
                     (UsefulBufC){item->val.string.ptr, item->val.string.len},
                     QCBOR_DECODE_MODE_MAP_AS_ARRAY);
    int32_t result = suit_set_text(&text_context, item, error, true, text);
    QCBORDecode_Finish(&text_context);
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
            printf("verification is not implemented for SUIT_Digest.algorithm_id=%d\n", digest->algorithm_id);
        default:
            result = SUIT_UNEXPECTED_ERROR;
    }
    return result;
}

int32_t suit_set_manifest(QCBORDecodeContext *context,
                          QCBORItem *item,
                          QCBORError *error,
                          bool next,
                          suit_manifest_t *manifest,
                          suit_digest_t *digest) {
    // printf("suit_set_manifest\n");
    int32_t result = SUIT_SUCCESS;
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        suit_debug_print(context, item, error, "suit_set_manifest", QCBOR_TYPE_BYTE_STRING);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }

    /* verify the SUIT_Manifest with SUIT_Digest */
    suit_buf_t buf;
    size_t rollback = suit_qcbor_calc_rollback(item);
    buf.ptr = item->val.string.ptr - rollback;
    buf.len = item->val.string.len + rollback;
    result = suit_verify_digest(&buf, digest);
    if (result != SUIT_SUCCESS) {
        suit_debug_print(context, item, error, "suit_set_manifest@verify-digest", QCBOR_TYPE_BYTE_STRING);
        return result;
    }

    QCBORDecodeContext manifest_context;
    QCBORDecode_Init(&manifest_context,
                     (UsefulBufC){item->val.string.ptr, item->val.string.len},
                     QCBOR_DECODE_MODE_NORMAL);

    if (!suit_qcbor_get_next(&manifest_context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    uint16_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        if (!suit_qcbor_get_next(&manifest_context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        switch (item->label.uint64) {
            case SUIT_MANIFEST_VERSION:
                if (item->uDataType != QCBOR_TYPE_INT64) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                manifest->version = item->val.uint64;
                break;
            case SUIT_MANIFEST_SEQUENCE_NUMBER:
                if (item->uDataType != QCBOR_TYPE_INT64) {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                    break;
                }
                manifest->sequence_number = item->val.uint64;
                break;
            case SUIT_COMMON:
                result = suit_set_common(&manifest_context, item, error, false, &manifest->common);
                break;
            case SUIT_PAYLOAD_FETCH:
                result = suit_set_command_sequence_from_bytes(&manifest_context, item, error, false, &manifest->sev_man_mem.payload_fetch);
                break;
            case SUIT_INSTALL:
                if (item->uDataType == QCBOR_TYPE_ARRAY) {
                    /* SUIT_Digest */
                    result = suit_set_digest(&manifest_context, item, error, false, &manifest->sev_mem_dig.install);
                }
                else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                    /* bstr .cbor SUIT_Command_Sequence */
                    result = suit_set_command_sequence_from_bytes(&manifest_context, item, error, false, &manifest->sev_man_mem.install);
                }
                else {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                break;
            case SUIT_TEXT:
                if (item->uDataType == QCBOR_TYPE_ARRAY) {
                    /* SUIT_Digest */
                    result = suit_set_digest(&manifest_context, item, error, false, &manifest->sev_mem_dig.text);
                }
                else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                    /* bstr .cbor SUIT_Text_Map */
                    result = suit_set_text_from_bytes(&manifest_context, item, error, false, &manifest->sev_man_mem.text);
                }
                else {
                    result = SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                break;
            /* SUIT_Unseverabme_Members */
            case SUIT_VALIDATE:
                result = suit_set_command_sequence_from_bytes(&manifest_context, item, error, false, &manifest->unsev_mem.validate);
                break;
            case SUIT_LOAD:
                result = suit_set_command_sequence_from_bytes(&manifest_context, item, error, false, &manifest->unsev_mem.load);
                break;
            case SUIT_RUN:
                result = suit_set_command_sequence_from_bytes(&manifest_context, item, error, false, &manifest->unsev_mem.run);
                break;
            case SUIT_REFERENCE_URI:
            case SUIT_DEPENDENCY_RESOLUTION:
            case SUIT_COSWID:
            default:
                // TODO
                printf("suit_set_manifest skip label %lu\n", item->label.uint64);
                return SUIT_UNEXPECTED_ERROR;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    QCBORDecode_Finish(&manifest_context);
    return result;
}

int32_t suit_set_authentication_wrapper(QCBORDecodeContext *context,
                                        QCBORItem *item,
                                        QCBORError *error,
                                        bool next,
                                        suit_authentication_wrapper_t *wrapper,
                                        const char *public_key) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_ARRAY) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }

    if (item->val.uCount >= SUIT_MAX_ARRAY_LENGTH) {
        return SUIT_NO_MEMORY;
    }
    int32_t result = SUIT_SUCCESS;

    wrapper->len = item->val.uCount;
    for (size_t i = 0; i < wrapper->len; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        suit_buf_t buf;
        buf.ptr = item->val.string.ptr;
        buf.len = item->val.string.len;

        if (i == 0) {
            result = suit_set_digest_from_buf(&buf, &wrapper->digest[i]);
        }
        else {
            result = suit_set_authentication_block_from_buf(&buf, &wrapper->digest[i], public_key);
        }
        if (result != SUIT_SUCCESS) {
            wrapper->len = i;
            break;
        }
    }
    return result;
}

int32_t suit_set_authentication_wrapper_from_buf(suit_buf_t *buf,
                                                 suit_authentication_wrapper_t *wrapper,
                                                 const char *public_key) {
    QCBORDecodeContext auth_context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&auth_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_set_authentication_wrapper(&auth_context, &item, &error, true, wrapper, public_key);
    QCBORDecode_Finish(&auth_context);
    return result;
}

int32_t suit_set_envelope(QCBORDecodeContext *context,
                          QCBORItem *item,
                          QCBORError *error,
                          bool next,
                          suit_envelope_t *envelope,
                          const char *public_key) {
    if (next && !suit_qcbor_get_next(context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    else if (item->uDataType != QCBOR_TYPE_MAP) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    int32_t result = SUIT_SUCCESS;
    uint16_t map_count = item->val.uCount;
    bool is_authentication_set = false;
    suit_buf_t buf;
    for (size_t i = 0; i < map_count; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_UNEXPECTED_ERROR;
        }
        switch (item->label.uint64) {
            case SUIT_AUTHENTICATION:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                buf.ptr = item->val.string.ptr;
                buf.len = item->val.string.len;
                result = suit_set_authentication_wrapper_from_buf(&buf, &envelope->wrapper, public_key);
                if (result == SUIT_SUCCESS) {
                    is_authentication_set = true;
                }
                break;
            case SUIT_MANIFEST:
                if (!is_authentication_set) {
                    return SUIT_FAILED_TO_VERIFY;
                }
                result = suit_set_manifest(context, item, error, false, &envelope->manifest, &envelope->wrapper.digest[envelope->wrapper.len - 1]);
                break;
            /* SUIT_Severable_Manifest_members */
            case SUIT_INSTALL:
                if (!is_authentication_set) {
                    return SUIT_FAILED_TO_VERIFY;
                }
                result = suit_set_command_sequence_from_bytes(context, item, error, false, &envelope->sev_man_mem.install);
                break;
            case SUIT_TEXT:
                if (!is_authentication_set) {
                    return SUIT_FAILED_TO_VERIFY;
                }
                result = suit_set_text_from_bytes(context, item, error, false, &envelope->sev_man_mem.text);
                break;
            case SUIT_COSWID:
                if (!is_authentication_set) {
                    return SUIT_FAILED_TO_VERIFY;
                }
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                envelope->sev_man_mem.coswid.ptr = item->val.string.ptr;
                envelope->sev_man_mem.coswid.len = item->val.string.len;
                break;
            case SUIT_DELEGATION:
            case SUIT_DEPENDENCY_RESOLUTION:
            case SUIT_PAYLOAD_FETCH:
            default:
                // TODO
                printf("SUIT_Envelope label %ld is not implemented", item->label.int64);
                result = SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }

    return SUIT_SUCCESS;
}

