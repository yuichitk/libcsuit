/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "suit_common.h"
#include "suit_manifest_data.h"

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

int32_t suit_set_parameters_list(QCBORDecodeContext *context,
                                 QCBORItem *item,
                                 QCBORError *error,
                                 suit_parameters_list_t *params_list) {
    if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    params_list->len = item->val.uCount;
    // printf("suit_set_parameters_list : len = %lu\n", params_list->len);
    for (size_t i = 0;i < params_list->len; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        params_list->params[i].label = item->label.uint64;
        switch (params_list->params[i].label) {
            case 1:
            case 2:
            case 3:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    printf("\nsuit_set_parameters_list : Error! uDataType = %d\n", item->uDataType);
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                params_list->params[i].value.string.ptr = item->val.string.ptr;
                params_list->params[i].value.string.len = item->val.string.len;
                break;
            case 14:
                if (item->uDataType != QCBOR_TYPE_INT64) {
                    printf("\nsuit_set_parameters_list : Error! uDataType = %d\n", item->uDataType);
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                params_list->params[i].value.uint64 = item->val.uint64;
                break;
            case 21:
                if (item->uDataType != QCBOR_TYPE_TEXT_STRING) {
                    printf("\nsuit_set_parameters_list : Error! uDataType = %d\n", item->uDataType);
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                params_list->params[i].value.string.ptr = item->val.string.ptr;
                params_list->params[i].value.string.len = item->val.string.len;
                break;
            default:
                return SUIT_UNEXPECTED_ERROR;
        }
    }
    return SUIT_SUCCESS;
}

int32_t suit_set_cmd_seq(QCBORDecodeContext *context,
                         QCBORItem *item,
                         QCBORError *error,
                         suit_command_sequence_t *cmd_seq) {
    if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    int32_t result = 0;
    const uint16_t array_count = item->val.uCount;
    // printf("suit_set_cmd_seq : array_count = %u\n", array_count);
    size_t commands_index = 0;
    for (size_t i = 0; i < array_count;) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_INT64)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        cmd_seq->commands[commands_index].label = item->val.uint64;
        // printf("suit_set_cmd_seq : label = %u\n", cmd_seq->commands[commands_index].label);
        switch (cmd_seq->commands[commands_index].label) {
            case SUIT_CONDITION_VENDOR_IDENTIFIER:
            case SUIT_CONDITION_CLASS_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_MATCH:
            case SUIT_DIRECTIVE_FETCH:
                if (!suit_qcbor_get_next_uint(context, item, error)) {
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                cmd_seq->commands[commands_index].value.uint64 = item->val.uint64;
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                result = suit_set_parameters_list(context,
                                                  item,
                                                  error,
                                                  &cmd_seq->commands[commands_index].value.params_list);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_CONDITION_USE_BEFORE:
            case SUIT_CONDITION_COMPONENT_OFFSET:
            case SUIT_CONDITION_ABORT:
            case SUIT_CONDITION_DEVICE_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_NOT_MATCH:
            case SUIT_CONDITION_MINIMUM_BATTERY:
            case SUIT_CONDITION_UPDATE_AUTHORIZED:
            case SUIT_CONDITION_VERSION:
            case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
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
                // TODO
                suit_debug_print(context, item, error,
                                 "suit_set_command_seq(skipping)",
                                 QCBOR_TYPE_ANY);
                suit_qcbor_skip_any(context, item, error);
                break;
            default:
                return SUIT_UNEXPECTED_ERROR;
        }
        commands_index++;
        i += 2;
    }
    cmd_seq->len = commands_index;
    return SUIT_SUCCESS;
}

int32_t suit_set_cmd_seq_from_bytes(QCBORDecodeContext *context,
                                    QCBORItem *item,
                                    QCBORError *error,
                                    suit_command_sequence_t *cmd_seq) {
    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("\nsuit_set_cmd_seq_from_bytes : Error! uDataType = %d\n", item->uDataType);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    QCBORDecodeContext cmd_seq_context;
    QCBORDecode_Init(&cmd_seq_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);

    int32_t result = suit_set_cmd_seq(&cmd_seq_context, item, error, cmd_seq);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBORDecode_Finish(&cmd_seq_context);
    return SUIT_SUCCESS;
}

int32_t suit_set_sev_cmd_seq_from_bytes(QCBORDecodeContext *context,
                                        QCBORItem *item,
                                        QCBORError *error,
                                        suit_sev_command_sequence_t *sev_cmd_seq) {
    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("\nsuit_set_sev_cmd_seq_from_bytes : Error! uDataType = %d\n", item->uDataType);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    QCBORDecodeContext sev_cmd_seq_context;
    QCBORDecode_Init(&sev_cmd_seq_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);

    // TODO : Check SUIT_Digest
    int32_t result = suit_set_cmd_seq(&sev_cmd_seq_context,
                                      item,
                                      error,
                                      &sev_cmd_seq->value.cmd_seq);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBORDecode_Finish(&sev_cmd_seq_context);
    return SUIT_SUCCESS;
}

int32_t suit_set_components(QCBORDecodeContext *context,
                            QCBORItem *item,
                            QCBORError *error,
                            suit_components_t *components) {
    if (item->uDataType != QCBOR_TYPE_ARRAY) {
        suit_debug_print(context, item, error, "suit_set_components", QCBOR_TYPE_ARRAY);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    components->len = item->val.uCount;
    for (size_t i = 0; i < components->len; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ARRAY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        components->comp_id[i].len = item->val.uCount;
        for (size_t j = 0; j < components->comp_id[i].len; j++) {
            if (!qcbor_get_next(context, item, error, QCBOR_TYPE_BYTE_STRING)) {
                return SUIT_INVALID_TYPE_OF_ARGUMENT;
            }
            components->comp_id[i].identifer[j].ptr = item->val.string.ptr;
            components->comp_id[i].identifer[j].len = item->val.string.len;
        }
    }

    return SUIT_SUCCESS;
}

int32_t suit_set_common(QCBORDecodeContext *context,
                        QCBORItem *item,
                        QCBORError *error,
                        suit_common_t *common) {
    // printf("suit_set_common\n");
    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("\nsuit_set_common : Error! uDataType = %d\n", item->uDataType);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    QCBORDecodeContext common_context;
    QCBORDecode_Init(&common_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);

    if (!suit_qcbor_get_next(&common_context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    int32_t result = 0;
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
                result = suit_set_components(&common_context,
                                             item,
                                             error,
                                             &common->components);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_COMMON_SEQUENCE:
                result = suit_set_cmd_seq_from_bytes(&common_context,
                                                     item,
                                                     error,
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

int32_t suit_set_manifest(QCBORDecodeContext *context,
                          QCBORItem *item,
                          QCBORError *error,
                          suit_manifest_t *manifest) {
    // printf("suit_set_manifest\n");
    int32_t result = 0;
    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("\nsuit_set_manifest : Error! uDataType = %d\n", item->uDataType);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }

    QCBORDecodeContext manifest_context;
    QCBORDecode_Init(&manifest_context,
                     item->val.string,
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
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                manifest->version = item->val.uint64;
                break;
            case SUIT_MANIFEST_SEQUENCE_NUMBER:
                if (item->uDataType != QCBOR_TYPE_INT64) {
                    return SUIT_INVALID_TYPE_OF_ARGUMENT;
                }
                manifest->sequence_number = item->val.uint64;
                break;
            case SUIT_COMMON:
                result = suit_set_common(&manifest_context, item, error, &manifest->common);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_INSTALL:
                result = suit_set_sev_cmd_seq_from_bytes(&manifest_context, item, error, &manifest->install);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_VALIDATE:
                result = suit_set_cmd_seq_from_bytes(&manifest_context, item, error, &manifest->validate);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_REFERENCE_URI:
            case SUIT_DEPENDENCY_RESOLUTION:
            case SUIT_PAYLOAD_FETCH:
            case SUIT_LOAD:
            case SUIT_RUN:
            case SUIT_TEXT:
            case SUIT_COSWID:
                // TODO
                suit_debug_print(&manifest_context, item, error,
                                 "suit_set_manifest(skipping)",
                                 QCBOR_TYPE_ANY);
                suit_qcbor_skip_any(&manifest_context, item, error);
                break;
            default:
                break;
        }
    }
    QCBORDecode_Finish(&manifest_context);
    return SUIT_SUCCESS;
}

int32_t suit_set_auth_wrapper(QCBORDecodeContext *context,
                              QCBORItem *item,
                              QCBORError *error,
                              suit_authentication_wrapper_t *wrapper) {
    // printf("suit_set_auth_wrapper\n");
    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("\nsuit_set_auth_wrapper : Error! uDataType = %d\n", item->uDataType);
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }

    QCBORDecodeContext auth_wrapper_context;
    QCBORDecode_Init(&auth_wrapper_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);

    if (!suit_qcbor_get_next(&auth_wrapper_context, item, error, QCBOR_TYPE_ARRAY)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    wrapper->len = item->val.uCount;
    for (size_t i = 0; i < wrapper->len; i++) {
        if (!suit_qcbor_get_next(&auth_wrapper_context, item, error, QCBOR_TYPE_BYTE_STRING)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        wrapper->auth_block[i].len = item->val.string.len;
        wrapper->auth_block[i].ptr = item->val.string.ptr;
    }

    QCBORDecode_Finish(&auth_wrapper_context);
    return SUIT_SUCCESS;
}

int32_t suit_set_envelope(QCBORDecodeContext *context, QCBORItem *item, QCBORError *error, suit_envelope_t *envelope) {
    int32_t result = 0;
    envelope->wrapper.len = 0;
    if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_MAP)) {
        return SUIT_INVALID_TYPE_OF_ARGUMENT;
    }
    uint16_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        if (!suit_qcbor_get_next(context, item, error, QCBOR_TYPE_ANY)) {
            return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
        switch (item->label.uint64) {
            case SUIT_DELEGATION:
                // TODO
                suit_debug_print(context, item, error,
                                 "suit_set_delegation(skipping)",
                                 QCBOR_TYPE_BYTE_STRING);
                suit_qcbor_skip_any(context, item, error);
                break;
            case SUIT_AUTHENTICATION:
                result = suit_set_auth_wrapper(context, item, error, &envelope->wrapper);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            case SUIT_MANIFEST:
                result = suit_set_manifest(context, item, error, &envelope->manifest);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                break;
            default:
                return SUIT_INVALID_TYPE_OF_ARGUMENT;
        }
    }

    return SUIT_SUCCESS;
}
