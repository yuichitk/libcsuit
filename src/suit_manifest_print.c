/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*!
    \file   suit_manifest_print.c

    \brief  This implements libcsuit printing

    Call these functions if you want to print the decoded structures and definitions.
 */

#include "csuit/suit_manifest_print.h"

const char* suit_err_to_str(suit_err_t error) {
    switch(error) {
    case SUIT_SUCCESS:
        return "SUIT_SUCCESS";
    case SUIT_ERR_FATAL:
        return "SUIT_ERR_FATAL";
    case SUIT_ERR_NO_MEMORY:
        return "SUIT_ERR_NO_MEMORY";
    case SUIT_ERR_INVALID_TYPE_OF_ARGUMENT:
        return "SUIT_INVALID_TYPE_OF_ARGUMENT";
    case SUIT_ERR_NO_MORE_ITEMS:
        return "SUIT_ERR_NO_MORE_ITEMS";
    case SUIT_ERR_NOT_IMPLEMENTED:
        return "SUIT_ERR_NOT_IMPLEMENTED";
    case SUIT_ERR_FAILED_TO_VERIFY:
        return "SUIT_ERR_FAILED_TO_VERIFY";
    case SUIT_ERR_AUTHENTICATION_POSITION:
        return "SUIT_ERR_AUTHENTICATION_POSITION";
    case SUIT_ERR_REDUNDANT:
        return "SUIT_ERR_REDUNDANT";
    case SUIT_ERR_INVALID_TYPE_OF_KEY:
        return "SUIT_ERR_INVALID_TYPE_OF_KEY";
    case SUIT_ERR_INVALID_MANIFEST_VERSION:
        return "SUIT_ERR_INVALID_MANIFEST_VERSION";
    case SUIT_ERR_INVALID_KEY:
        return "SUIT_ERR_INVALID_KEY";
    case SUIT_ERR_NO_CALLBACK:
        return "SUIT_ERR_NO_CALLBACK";
    case SUIT_ERR_NO_ARGUMENT:
        return "SUIT_ERR_NO_ARGUMENT";
    case SUIT_ERR_TRY_OUT:
        return "SUIT_ERR_TRY_OUT";
    case SUIT_ERR_ABORT:
        return "SUIT_ERR_ABORT";
    default:
        return "SUIT_ERR_UNKNOWN";
    }
}

const char* suit_envelope_key_to_str(suit_envelope_key_t envelope_key) {
    switch (envelope_key) {
    case SUIT_DELEGATION:
        return "delegation";
    case SUIT_AUTHENTICATION:
        return "authentication";
    case SUIT_MANIFEST:
        return "manifest";
    default:
        return NULL;
    }
}

const char* suit_manifest_key_to_str(suit_manifest_key_t manifest_key) {
    switch (manifest_key) {
    case SUIT_MANIFEST_VERSION:
        return "manifest-version";
    case SUIT_MANIFEST_SEQUENCE_NUMBER:
        return "manifest-sequence-number";
    case SUIT_COMMON:
        return "common";
    case SUIT_REFERENCE_URI:
        return "reference-uri";
    case SUIT_DEPENDENCY_RESOLUTION:
        return "dependency-resolution";
    case SUIT_PAYLOAD_FETCH:
        return "payload-fetch";
    case SUIT_INSTALL:
        return "install";
    case SUIT_VALIDATE:
        return "validate";
    case SUIT_LOAD:
        return "load";
    case SUIT_RUN:
        return "run";
    case SUIT_TEXT:
        return "text";
    case SUIT_COSWID:
        return "coswid";
    default:
        return NULL;
    }
}

const char* suit_common_key_to_str(suit_common_key_t common_key) {
    switch (common_key) {
    case SUIT_DEPENDENCIES:
        return "dependencies";
    case SUIT_COMPONENTS:
        return "components";
    case SUIT_COMMON_SEQUENCE:
        return "common-sequence";
    default:
        return NULL;
    }
}

const char* suit_command_sequence_key_to_str(suit_con_dir_key_t condition_directive) {
    switch (condition_directive) {
    case SUIT_CONDITION_VENDOR_IDENTIFIER:
        return "condition-vendor-identifier";
    case SUIT_CONDITION_CLASS_IDENTIFIER:
        return "condition-class-identifier";
    case SUIT_CONDITION_IMAGE_MATCH:
        return "condition-image-match";
    case SUIT_CONDITION_USE_BEFORE:
        return "condition-use-before";
    case SUIT_CONDITION_COMPONENT_SLOT:
        return "condition-component-slot";
    case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
        return "directive-set-component-index";
    case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
        return "directive-set-dependency-index";
    case SUIT_CONDITION_ABORT:
        return "condition-abort";
    case SUIT_DIRECTIVE_TRY_EACH:
        return "directive-try-each";
    case SUIT_DIRECTIVE_DO_EACH:
        return "directive-do-each";
    case SUIT_DIRECTIVE_MAP_FILTER:
        return "directive-map-filter";
    case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
        return "directive-process-dependency";
    case SUIT_DIRECTIVE_SET_PARAMETERS:
        return "directive-set-parameters";
    case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
        return "directive-override-parameters";
    case SUIT_DIRECTIVE_FETCH:
        return "directive-fetch";
    case SUIT_DIRECTIVE_COPY:
        return "directive-copy";
    case SUIT_DIRECTIVE_RUN:
        return "directive-run";
    case SUIT_CONDITION_DEVICE_IDENTIFIER:
        return "condition-device-identifier";
    case SUIT_CONDITION_IMAGE_NOT_MATCH:
        return "condition-image-not-match";
    case SUIT_CONDITION_MINIMUM_BATTERY:
        return "condition-minimum-battery";
    case SUIT_CONDITION_UPDATE_AUTHORIZED:
        return "condition-update-authorized";
    case SUIT_CONDITION_VERSION:
        return "condition-version";
    case SUIT_DIRECTIVE_WAIT:
        return "directive-wait";
    case SUIT_DIRECTIVE_FETCH_URI_LIST:
        return "directive-fetch-uri-list";
    case SUIT_DIRECTIVE_SWAP:
        return "directive-swap";
    case SUIT_DIRECTIVE_RUN_SEQUENCE:
        return "directive-run-sequence";
    case SUIT_DIRECTIVE_UNLINK:
        return "directive-unlink";
    default:
        return NULL;
    }
}

const char* suit_parameter_key_to_str(suit_parameter_key_t parameter) {
    switch (parameter) {
    case SUIT_PARAMETER_VENDOR_IDENTIFIER:
        return "vendor-id";
    case SUIT_PARAMETER_CLASS_IDENTIFIER:
        return "class-id";
    case SUIT_PARAMETER_IMAGE_DIGEST:
        return "image-digest";
    case SUIT_PARAMETER_USE_BEFORE:
        return "use-before";
    case SUIT_PARAMETER_COMPONENT_SLOT:
        return "component-slot";
    case SUIT_PARAMETER_STRICT_ORDER:
        return "strict-order";
    case SUIT_PARAMETER_SOFT_FAILURE:
        return "soft-failure";
    case SUIT_PARAMETER_IMAGE_SIZE:
        return "image-size";
    case SUIT_PARAMETER_ENCRYPTION_INFO:
        return "encryption-info";
    case SUIT_PARAMETER_COMPRESSION_INFO:
        return "compression-info";
    case SUIT_PARAMETER_UNPACK_INFO:
        return "unpack-info";
    case SUIT_PARAMETER_URI:
        return "uri";
    case SUIT_PARAMETER_SOURCE_COMPONENT:
        return "source-component";
    case SUIT_PARAMETER_RUN_ARGS:
        return "run-args";
    case SUIT_PARAMETER_DEVICE_IDENTIFIER:
        return "device-identifier";
    case SUIT_PARAMETER_MINIMUM_BATTERY:
        return "minimum-battery";
    case SUIT_PARAMETER_UPDATE_PRIORITY:
        return "update-priority";
    case SUIT_PARAMETER_VERSION:
        return "version";
    case SUIT_PARAMETER_WAIT_INFO:
        return "wait-info";
    case SUIT_PARAMETER_URI_LIST:
        return "uri-list";
    default:
        return NULL;
    }
}

const char* suit_info_key_to_str(const suit_info_key_t info_key) {
    switch (info_key) {
    case SUIT_INFO_DEFAULT:
        return "default";
    case SUIT_INFO_ENCRYPTION:
        return "SUIT_Encryption_Info";
    case SUIT_INFO_COMPRESSION:
        return "SUIT_Compression_Info";
    case SUIT_INFO_UNPACK:
        return "SUIT_Unpack_Info";
    default:
        return NULL;
    }
}

const char* suit_compression_algorithm_to_str(const suit_compression_algorithm_t algorithm) {
    switch (algorithm) {
    case SUIT_COMPRESSION_ALGORITHM_ZLIB:
        return "zlib";
    case SUIT_COMPRESSION_ALGORITHM_BROTLI:
        return "brotli";
    case SUIT_COMPRESSION_ALGORITHM_ZSTD:
        return "zstd";
    default:
        return NULL;
    }
}

const char* suit_unpack_algorithm_to_str(const suit_unpack_algorithm_t algorithm) {
    switch (algorithm) {
    case SUIT_UNPACK_ALGORITHM_HEX:
        return "HEX";
    case SUIT_UNPACK_ALGORITHM_ELF:
        return "ELF";
    case SUIT_UNPACK_ALGORITHM_COFF:
        return "COFF";
    case SUIT_UNPACK_ALGORITHM_SREC:
        return "SREC";
    default:
        return NULL;
    }
}

suit_err_t suit_print_hex_in_max(const uint8_t *array, const size_t size, const size_t max_print_size) {
    suit_err_t result = SUIT_SUCCESS;
    if (size <= max_print_size) {
        result = suit_print_hex(array, size);
    }
    else {
        result = suit_print_hex(array, max_print_size);
        printf("..");
    }
    return result;
}

suit_err_t suit_print_hex(const uint8_t *array, size_t size) {
    if (array == NULL) {
        return SUIT_ERR_FATAL;
    }
    for (size_t i = 0; i < size; i++) {
        printf("0x%02x ", (unsigned char)array[i]);
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_bytestr(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL)
        return( SUIT_ERR_FATAL );

    for(unsigned int idx=0; idx < len; idx++)
    {
        printf("%02X", bytes[idx]);
    }
    return( SUIT_ERR_FATAL );
}

suit_err_t suit_print_string(const suit_buf_t *string) {
    if (string == NULL) {
        return SUIT_ERR_FATAL;
    }
    size_t print_len = (SUIT_MAX_PRINT_TEXT_COUNT < string->len) ? SUIT_MAX_PRINT_TEXT_COUNT : string->len;
    printf("\"");
    for (size_t j = 0; j < print_len; j++) {
        putchar(string->ptr[j]);
    }
    printf("\"");
    if (print_len < string->len) {
        printf("..");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_compression_info(const suit_buf_t *buf, const uint32_t indent_space) {
    if (buf == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_compression_info_t compression_info = {0};
    suit_err_t result = suit_decode_compression_info(SUIT_DECODE_MODE_STRICT, buf, &compression_info);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    if (compression_info.algorithm != SUIT_COMPRESSION_ALGORITHM_INVALID) {
        printf("%*scompression-algorithm : %d\n", indent_space, "", compression_info.algorithm);
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space) {
    suit_err_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        printf("%*s%s : ", indent_space, "", suit_parameter_key_to_str(params_list->params[i].label));
        switch (params_list->params[i].label) {
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
                result = suit_print_hex_in_max(params_list->params[i].value.string.ptr,
                                 params_list->params[i].value.string.len,
                                 SUIT_MAX_PRINT_BYTE_COUNT);
                printf("\n");
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                printf("SUIT_Digest\n");
                result = suit_print_digest(&params_list->params[i].value.digest, indent_space + 2);
                break;
            case SUIT_PARAMETER_COMPONENT_SLOT:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                printf("%lu\n", params_list->params[i].value.uint64);
                break;
            case SUIT_PARAMETER_URI:
                if (params_list->params[i].value.string.len > 0) {
                    result = suit_print_string(&params_list->params[i].value.string);
                }
                else {
                    printf("NULL");
                }
                printf("\n");
                break;
            case SUIT_PARAMETER_COMPRESSION_INFO:
                printf("SUIT_Compression_Info\n");
                if (params_list->params[i].value.string.len > 0) {
                    result = suit_print_compression_info(&params_list->params[i].value.string, indent_space + 2);
                }
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
                result = SUIT_ERR_FATAL;
                printf("?\n");
                break;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_cmd_seq(uint8_t mode, const suit_command_sequence_t *cmd_seq, const uint32_t indent_space) {
    suit_err_t result = SUIT_SUCCESS;
    suit_command_sequence_t tmp_cmd_seq;
    for (size_t i = 0; i < cmd_seq->len; i++) {
        printf("%*s%s : ", indent_space, "", suit_command_sequence_key_to_str(cmd_seq->commands[i].label));
        switch (cmd_seq->commands[i].label) {
            case SUIT_CONDITION_VENDOR_IDENTIFIER:
            case SUIT_CONDITION_CLASS_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_MATCH:
            case SUIT_CONDITION_COMPONENT_SLOT:
            case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
            case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
            case SUIT_DIRECTIVE_FETCH:
            case SUIT_DIRECTIVE_COPY:
            case SUIT_DIRECTIVE_RUN:
            case SUIT_DIRECTIVE_UNLINK:
                printf("%lu\n", cmd_seq->commands[i].value.uint64);
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                if (cmd_seq->commands[i].value.params_list.len > 0) {
                    printf("SUIT_Parameters\n");
                    result = suit_print_suit_parameters_list(&cmd_seq->commands[i].value.params_list, indent_space + 2);
                }
                else {
                    printf("\n");
                }
                break;
            case SUIT_DIRECTIVE_TRY_EACH:
                printf("SUIT_Command_Sequence\n");
                result = suit_decode_command_sequence(mode, &cmd_seq->commands[i].value.string, &tmp_cmd_seq);
                if (result == SUIT_SUCCESS) {
                    result = suit_print_cmd_seq(mode, &tmp_cmd_seq, indent_space + 2);
                }
                else {
                    printf("%d?\n", result);
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
            case SUIT_DIRECTIVE_WAIT:
            case SUIT_DIRECTIVE_FETCH_URI_LIST:
            case SUIT_DIRECTIVE_SWAP:
            case SUIT_DIRECTIVE_RUN_SEQUENCE:
                result = SUIT_ERR_FATAL;
                printf("?\n");
                break;
            default:
                break;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_component_identifier(const suit_component_identifier_t *identifier) {
    if (identifier == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("[");
    for (size_t j = 0; j < identifier->len; j++) {
        suit_print_hex_in_max(identifier->identifier[j].ptr, identifier->identifier[j].len, SUIT_MAX_PRINT_BYTE_COUNT);
        printf(", ");
    }
    printf("]");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space) {
    if (digest == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (digest->algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*salgorithm-id : %d\n", indent_space, "", digest->algorithm_id);
    }
    if (digest->bytes.len > 0) {
        printf("%*sdigest-bytes : ", indent_space, "");
        result = suit_print_hex_in_max(digest->bytes.ptr, digest->bytes.len, SUIT_MAX_PRINT_BYTE_COUNT);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    return SUIT_SUCCESS;
}

int32_t suit_print_dependency(const suit_dependency_t *dependency, uint32_t indent_space) {
    if (dependency == NULL) {
        return SUIT_ERR_FATAL;
    }
    int32_t result = SUIT_SUCCESS;
    if (dependency->digest.algorithm_id == SUIT_ALGORITHM_ID_INVALID) {
        return SUIT_ERR_FATAL;
    }

    printf("%*sdependency-digest : SUIT_Digest\n", indent_space, "");
    result = suit_print_digest(&dependency->digest, indent_space + 2);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    if (dependency->prefix.len > 0) {
        printf("%*sdependency-prefix : ", indent_space, "");
        result = suit_print_component_identifier(&dependency->prefix);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }

    /* TODO: SUIT_Dependency-extensions */
    return SUIT_SUCCESS;
}

bool suit_text_component_have_something_to_print(const suit_text_component_t *text_component) {
    return (text_component->vendor_name.ptr != NULL ||
            text_component->model_name.ptr != NULL ||
            text_component->vendor_domain.ptr != NULL ||
            text_component->model_info.ptr != NULL ||
            text_component->component_description.ptr != NULL ||
            text_component->component_version.ptr != NULL ||
            text_component->version_required.ptr != NULL);
}

suit_err_t suit_print_text_component(const suit_text_component_t *text_component, const uint32_t indent_space) {
    if (text_component == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!suit_text_component_have_something_to_print(text_component)) {
        return SUIT_SUCCESS;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (text_component->vendor_name.ptr != NULL) {
        printf("%*stext-vendor-name : ", indent_space, "");
        result = suit_print_string(&text_component->vendor_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->model_name.ptr != NULL) {
        printf("%*stext-model-name : ", indent_space, "");
        result = suit_print_string(&text_component->model_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->vendor_domain.ptr != NULL) {
        printf("%*stext-vendor-domain : ", indent_space, "");
        result = suit_print_string(&text_component->vendor_domain);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->model_info.ptr != NULL) {
        printf("%*stext-vendor-info : ", indent_space, "");
        result = suit_print_string(&text_component->model_info);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->component_description.ptr != NULL) {
        printf("%*stext-component-description : ", indent_space, "");
        result = suit_print_string(&text_component->component_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (text_component->component_version.ptr != NULL) {
        printf("%*stext-component-version : ", indent_space, "");
        result = suit_print_string(&text_component->component_version);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->version_required.ptr != NULL) {
        printf("%*stext-version-required : ", indent_space, "");
        result = suit_print_string(&text_component->version_required);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    return SUIT_SUCCESS;
}

bool suit_whether_print_now(bool in_suit_manifest, uint8_t status) {
    return ((in_suit_manifest && (status & SUIT_SEVERABLE_IN_MANIFEST)) ||
           (!in_suit_manifest && (status & SUIT_SEVERABLE_IN_ENVELOPE)));
}

bool suit_is_severable_manifest_member_verified(uint8_t status) {
    return (status & SUIT_SEVERABLE_IS_VERIFIED);
}

char *suit_str_verified(bool verified) {
    return (verified) ? "verified" : "not verified";
}

char *suit_str_member_is_verified(uint8_t status) {
    return suit_str_verified(suit_is_severable_manifest_member_verified(status));
}

bool suit_text_have_something_to_print(const suit_text_t *text) {
    return (text->manifest_description.ptr != NULL ||
            text->update_description.ptr != NULL ||
            text->manifest_json_source.ptr != NULL ||
            text->manifest_yaml_source.ptr != NULL ||
            text->component_len > 0);
}

suit_err_t suit_print_text(const suit_text_t *text, const uint8_t status, const uint32_t indent_space) {
    if (text == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!suit_text_have_something_to_print(text)) {
        return SUIT_SUCCESS;
    }
    suit_err_t result = SUIT_SUCCESS;
    printf("%*stext(%s) : SUIT_Text_Map\n", indent_space, "", suit_str_member_is_verified(status));
    if (text->manifest_description.ptr != NULL) {
        printf("%*stext-manifest-description : ", indent_space + 2, "");
        result = suit_print_string(&text->manifest_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text->update_description.ptr != NULL) {
        printf("%*stext-update-description : ", indent_space + 2, "");
        result = suit_print_string(&text->update_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text->manifest_json_source.ptr != NULL) {
        printf("%*stext-manifest-json-source : ", indent_space + 2, "");
        result = suit_print_string(&text->manifest_json_source);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text->manifest_yaml_source.ptr != NULL) {
        printf("%*stext-manifest-yaml-source : ", indent_space + 2, "");
        result = suit_print_string(&text->manifest_yaml_source);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    for (size_t i = 0; i < text->component_len; i++) {
        printf("%*s", indent_space + 2, "");
        result = suit_print_component_identifier(&text->component[i].key);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf(" :\n");
        result = suit_print_text_component(&text->component[i].text_component, indent_space + 4);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_unseverable_members(uint8_t mode, const suit_unseverable_members_t *unsev_mem, uint32_t indent_space) {
    if (unsev_mem == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (unsev_mem->validate.len > 0) {
        printf("%*svalidate : SUIT_Command_Sequence\n", indent_space, "");
        result = suit_print_cmd_seq(mode, &unsev_mem->validate, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (unsev_mem->load.len > 0) {
        printf("%*sload : SUIT_Command_Sequence\n", indent_space , "");
        result = suit_print_cmd_seq(mode, &unsev_mem->load, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (unsev_mem->run.len > 0) {
        printf("%*srun : SUIT_Command_Sequence\n", indent_space, "");
        result = suit_print_cmd_seq(mode, &unsev_mem->run, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_severable_members_digests(const suit_severable_members_digests_t *sev_mem_dig, uint32_t indent_space) {
    if (sev_mem_dig == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (sev_mem_dig->dependency_resolution.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*sdependency-resolution : SUIT_Digest\n", indent_space, "");
        result = suit_print_digest(&sev_mem_dig->dependency_resolution, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (sev_mem_dig->payload_fetch.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*spayload-fetch : SUIT_Digest\n", indent_space, "");
        result = suit_print_digest(&sev_mem_dig->payload_fetch, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (sev_mem_dig->install.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*sinstall : SUIT_Digest\n", indent_space, "");
        result = suit_print_digest(&sev_mem_dig->install, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (sev_mem_dig->text.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*stext : SUIT_Digest\n", indent_space, "");
        result = suit_print_digest(&sev_mem_dig->text, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (sev_mem_dig->coswid.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*scoswid : SUIT_Digest\n", indent_space, "");
        result = suit_print_digest(&sev_mem_dig->coswid, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_severable_manifest_members(uint8_t mode, const suit_severable_manifest_members_t *sev_man_mem, uint32_t indent_space, bool in_suit_manifest) {
    if (sev_man_mem == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (suit_whether_print_now(in_suit_manifest, sev_man_mem->dependency_resolution_status)) {
        printf("%*sdependency-resolution(%s) : SUIT_Command_Sequence\n", indent_space, "", suit_str_member_is_verified(sev_man_mem->dependency_resolution_status));
        result = suit_print_cmd_seq(mode, &sev_man_mem->dependency_resolution, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (suit_whether_print_now(in_suit_manifest, sev_man_mem->payload_fetch_status)) {
        printf("%*spayload-fetch(%s) : SUIT_Command_Sequence\n", indent_space, "", suit_str_member_is_verified(sev_man_mem->payload_fetch_status));
        result = suit_print_cmd_seq(mode, &sev_man_mem->payload_fetch, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (suit_whether_print_now(in_suit_manifest, sev_man_mem->install_status)) {
        printf("%*sinstall(%s) : SUIT_Command_Sequence\n", indent_space, "", suit_str_member_is_verified(sev_man_mem->install_status));
        result = suit_print_cmd_seq(mode, &sev_man_mem->install, indent_space + 2);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (suit_whether_print_now(in_suit_manifest, sev_man_mem->text_status)) {
        result = suit_print_text(&sev_man_mem->text, sev_man_mem->text_status, indent_space);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (suit_whether_print_now(in_suit_manifest, sev_man_mem->coswid_status)) {
        printf("%*scoswid(%s) : ", indent_space, "", suit_str_member_is_verified(sev_man_mem->coswid_status));
        result = suit_print_hex_in_max(sev_man_mem->coswid.ptr, sev_man_mem->coswid.len, SUIT_MAX_PRINT_BYTE_COUNT);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_manifest(uint8_t mode, const suit_manifest_t *manifest, uint32_t indent_space) {
    if (manifest == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    printf("%*smanifest(%s) : SUIT_Manifest\n", indent_space, "", suit_str_verified(manifest->is_verified));
    printf("%*smanifest-version : %lu\n", indent_space + 2, "", manifest->version);
    printf("%*smanifest-sequence-number : %lu\n", indent_space + 2, "", manifest->sequence_number);

    printf("%*scommon : SUIT_Common\n", indent_space + 2, "");
    if (manifest->common.dependencies.len > 0) {
        printf("%*sdependencies : SUIT_Dependencies [\n", indent_space + 4, "");
        for (size_t i = 0; i < manifest->common.dependencies.len; i++) {
            result = suit_print_dependency(&manifest->common.dependencies.dependency[i], indent_space + 6);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        printf("%*s]\n", indent_space + 4, "");
    }

    if (manifest->common.components.len > 0) {
        printf("%*scomponents : [\n", indent_space + 4, "");
        for (size_t i = 0; i < manifest->common.components.len; i++) {
            printf("%*s", indent_space + 6, "");
            result = suit_print_component_identifier(&manifest->common.components.comp_id[i]);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            printf(",\n");
        }
        printf("%*s]\n", indent_space + 4, "");
    }
    if (manifest->common.cmd_seq.len > 0) {
        printf("%*scommon-sequence : SUIT_Common_Sequence\n", indent_space + 4, "");
        result = suit_print_cmd_seq(mode, &manifest->common.cmd_seq, indent_space + 6);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }

    /* SUIT_Severable_Manifest_Members */
    result = suit_print_severable_manifest_members(mode, &manifest->sev_man_mem, indent_space + 2, true);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* SUIT_Severable_Members_Digests */
    result = suit_print_severable_members_digests(&manifest->sev_mem_dig, indent_space + 2);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* SUIT_Unsevrable_Members */
    result = suit_print_unseverable_members(mode, &manifest->unsev_mem, indent_space + 2);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    return SUIT_SUCCESS;
}

suit_err_t suit_print_integrated_payload(uint8_t mode, const suit_payloads_t *payloads, const uint32_t indent_space) {
    for (size_t i = 0; i < payloads->len; i++) {
        printf("%*s\"%.*s\" : ", indent_space, "", (int)payloads->payload[i].key.len, (char *)payloads->payload[i].key.ptr);
        suit_print_hex_in_max(payloads->payload[i].bytes.ptr,
                              payloads->payload[i].bytes.len,
                              SUIT_MAX_PRINT_BYTE_COUNT);
        printf("\n");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_envelope(uint8_t mode, const suit_envelope_t *envelope, const uint32_t indent_space) {
    if (envelope == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    printf("%*sSUIT Manifest Envelope :\n", indent_space, "");
    // authentication-wrapper
    printf("%*sauthentication-wrapper : \n", indent_space + 2, "");
    printf("%*sdigest : SUIT_Digest \n", indent_space + 4, "");
    result = suit_print_digest(&envelope->wrapper.digest, indent_space + 6);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    // integrated-payload
    result = suit_print_integrated_payload(mode, &envelope->payloads, indent_space + 2);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    // manifest
    result = suit_print_manifest(mode, &envelope->manifest, indent_space + 2);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* SUIT_Severable_Manifest_Members */
    result = suit_print_severable_manifest_members(mode, &envelope->manifest.sev_man_mem, indent_space + 2, false);

    // TODO: SUIT_Integrated_Payload, SUIT_Integrated_Dependency, $$SUIT_Envelope_Extensions
    // TODO: (int => bstr)

    return SUIT_SUCCESS;
}
