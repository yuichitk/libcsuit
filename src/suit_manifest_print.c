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

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"
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
        return "(NULL)";
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
        return "(NULL)";
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
        return "(NULL)";
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
        return "(NULL)";
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
        return "(NULL)";
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
        return "(NULL)";
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
        return "(NULL)";
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
        return "(NULL)";
    }
}

const char* suit_cose_protected_key_to_str(int64_t key) {
    switch (key) {
    case 1:
        return "alg";
    case 2:
        return "crit";
    case 3:
        return "content type";
    case 4:
        return "kid";
    case 5:
        return "IV";
    case 6:
        return "Partial IV";
    case 7:
        return "counter signature";
    default:
        return "(UNKNOWN)";
    }
}

/*
 *  see https://datatracker.ietf.org/doc/draft-moran-suit-mti/
 */
const char* suit_cose_alg_to_str(int64_t id) {
    switch (id) {
    case -16:
        return "SHA-256";
    case -18:
        return "SHAKE128";
    case -43:
        return "SHA-384";
    case -44:
        return "SHA-512";
    case -45:
        return "SHAKE256";

    case 5:
        return "HMAC-256";
    case 6:
        return "HMAC-384";
    case 7:
        return "HMAC-512";

    case -7:
        return "ES256";
    case -8:
        return "EdDSA";
    case -35:
        return "ES384";
    case -36:
        return "es512";

    case -46:
        return "HSS-LMS";
/*
    case :
        return "XMSS";
    case :
        return "Falcon-512";
    case :
        return "SPHINCS+";
    case :
        return "Crystals-Dilithium";
        */

    case -3:
        return "A128";
    case -4:
        return "A192";
    case -5:
        return "A256";

/*
    case :
        return "HPKE";
        */
    case -25:
        return "ECDH-ES + HKDF-256";
    case -26:
        return "ECDH-ES + HKDF-512";
    case -29:
        return "ECDH-ES + A128KW";
    case -30:
        return "ECDH-ES + A192KW";
    case -31:
        return "ECDH-ES + A256KW";

/*
    case :
        return "CRYSTALS-KYBER";
        */

    case 1:
        return "A128GCM";
    case 2:
        return "A192GCM";
    case 3:
        return "A256GCM";
    case 24:
        return "ChaCha20/Poly1305";
    case 25:
        return "AES-MAC 128/128";
    case 26:
        return "AES-MAC 256/128";
    case 30:
        return "AES-CCM-16-128-128";
    case 31:
        return "AES-CCM-16-128-256";
    case 32:
        return "AES-CCM-64-128-128";
    case 33:
        return "AES-CCM-64-128-256";

    default:
        return "(UNKNOWN)";
    }
}

const char* suit_cose_protected_key_and_value_to_str(int64_t key, int64_t value) {
    switch (key) {
    case 1:
        return suit_cose_alg_to_str(value);
    default:
        return "(UNKNOWN)";
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
    printf("h'");
    for (size_t i = 0; i < size; i++) {
        printf("%02x", (unsigned char)array[i]);
    }
    printf("'");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_string(const suit_buf_t *string) {
    if (string == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("\"");
    for (size_t j = 0; j < string->len; j++) {
        putchar(string->ptr[j]);
    }
    printf("\"");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_uuid(const suit_buf_t *buf) {
    if (buf == NULL || buf->len != 16) {
        return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
    }
    int16_t digits[] = {4, 2, 2, 2, 6};
    int16_t pos = 0;
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < digits[i]; j++) {
            printf("%02x", (unsigned char)buf->ptr[pos]);
            pos++;
        }
        if (i != 4) {
            printf("-");
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_compression_info(const suit_buf_t *buf, const uint32_t indent_space, const uint32_t indent_delta) {
    if (buf == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_compression_info_t compression_info = {0};
    suit_err_t result = suit_decode_compression_info(SUIT_DECODE_MODE_STRICT, buf, &compression_info);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    if (compression_info.algorithm != SUIT_COMPRESSION_ALGORITHM_INVALID) {
        printf("%*s/ compression-algorithm / %d: %d / %s /\n", indent_space, "", SUIT_COMPRESSION_ALGORITHM, compression_info.algorithm, suit_compression_algorithm_to_str(compression_info.algorithm));
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space, const uint32_t indent_delta) {
    suit_err_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        printf("%*s/ %s / %ld: ", indent_space, "", suit_parameter_key_to_str(params_list->params[i].label), params_list->params[i].label);
        switch (params_list->params[i].label) {
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
                result = suit_print_hex(params_list->params[i].value.string.ptr,
                                        params_list->params[i].value.string.len);
                if (params_list->params[i].value.string.len == 16) {
                    // estimates this value as UUID
                    printf(" / ");
                    result = suit_print_uuid(&params_list->params[i].value.string);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    printf(" /");
                }
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                result = suit_print_digest(&params_list->params[i].value.digest, indent_space, indent_delta);
                break;
            case SUIT_PARAMETER_COMPONENT_SLOT:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                printf("%lu", params_list->params[i].value.uint64);
                break;
            case SUIT_PARAMETER_URI:
                if (params_list->params[i].value.string.len > 0) {
                    result = suit_print_string(&params_list->params[i].value.string);
                }
                else {
                    printf("NULL");
                }
                break;
            case SUIT_PARAMETER_COMPRESSION_INFO:
                printf("<< {\n");
                if (params_list->params[i].value.string.len > 0) {
                    result = suit_print_compression_info(&params_list->params[i].value.string, indent_space + indent_delta, indent_delta);
                }
                printf("%*s}", indent_space, "");
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
        if (i + 1 != params_list->len) {
            printf(",\n");
        }
        else {
            printf("\n");
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_cmd_seq(uint8_t mode, const suit_command_sequence_t *cmd_seq, const uint32_t indent_space, const uint32_t indent_delta) {
    suit_err_t result = SUIT_SUCCESS;
    suit_command_sequence_t tmp_cmd_seq;
    for (size_t i = 0; i < cmd_seq->len; i++) {
        printf("%*s/ %s / %ld, ", indent_space, "", suit_command_sequence_key_to_str(cmd_seq->commands[i].label), cmd_seq->commands[i].label);
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
                printf("%lu", cmd_seq->commands[i].value.uint64);
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                printf("{\n");
                if (cmd_seq->commands[i].value.params_list.len > 0) {
                    result = suit_print_suit_parameters_list(&cmd_seq->commands[i].value.params_list, indent_space + indent_delta, indent_delta);
                }
                printf("%*s}", indent_space, "");
                break;
            case SUIT_DIRECTIVE_TRY_EACH:
                printf("[\n");
                result = suit_decode_command_sequence(mode, &cmd_seq->commands[i].value.string, &tmp_cmd_seq);
                if (result == SUIT_SUCCESS) {
                    result = suit_print_cmd_seq(mode, &tmp_cmd_seq, indent_space + indent_delta, indent_delta);
                }
                printf("%*s]", indent_space, "");
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
                printf("?");
                break;
            default:
                break;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (i + 1 != cmd_seq->len) {
            printf(",\n");
        }
        else {
            printf("\n");
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_component_identifier(const suit_component_identifier_t *identifier) {
    if (identifier == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("[");
    for (size_t i = 0; i < identifier->len; i++) {
        suit_print_hex(identifier->identifier[i].ptr, identifier->identifier[i].len);
        if (i + 1 != identifier->len) {
            printf(", ");
        }
    }
    printf("]");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_signature(const suit_buf_t *signature, const uint32_t indent_space, const uint32_t indent_delta) {
    if (signature == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (signature->ptr != NULL && signature->len > 0) {
        QCBORDecodeContext auth_context;
        QCBORItem item;
        QCBORDecode_Init(&auth_context, (UsefulBufC){signature->ptr, signature->len}, QCBOR_DECODE_MODE_NORMAL);

        uint64_t puTags[1];
        QCBORTagListOut Out = {0, 1, puTags};
        QCBORDecode_GetNextWithTags(&auth_context, &item, &Out);
        if (item.uDataType != QCBOR_TYPE_ARRAY) {
            return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        }
        printf("%ld([\n", puTags[0]);

        printf("%*s/ protected: / << {", indent_space + indent_delta, "");
        QCBORDecode_EnterBstrWrapped(&auth_context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
        QCBORDecode_EnterMap(&auth_context, &item);
        size_t len = item.val.uCount;
        for (size_t i = 0; i < len; i++) {
            result = suit_qcbor_get_next(&auth_context, &item, QCBOR_TYPE_INT64);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            printf("\n%*s/ %s / %ld: %ld / %s /", indent_space + 2 * indent_delta, "", suit_cose_protected_key_to_str(item.label.int64), item.label.int64, item.val.int64, suit_cose_protected_key_and_value_to_str(item.label.int64, item.val.int64));
            if (i + 1 != len) {
                printf(",");
            }
        }
        printf("\n%*s} >>,\n", indent_space + indent_delta, "");
        QCBORDecode_ExitMap(&auth_context);
        QCBORDecode_ExitBstrWrapped(&auth_context);

        printf("%*s/ unprotected: / {", indent_space + indent_delta, "");
        QCBORDecode_EnterMap(&auth_context, &item);
        len = item.val.uCount;
        for (size_t i = 0; i < len; i++) {
            result = suit_qcbor_get_next(&auth_context, &item, QCBOR_TYPE_INT64);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            printf("\n%*s/ %s / %ld: %ld / %s /", indent_space + 2 * indent_delta, "", suit_cose_protected_key_to_str(item.label.int64), item.label.int64, item.val.int64, suit_cose_protected_key_and_value_to_str(item.label.int64, item.val.int64));
            if (i + 1 != len) {
                printf(",");
            }
        }
        printf("\n%*s},\n", indent_space + indent_delta, "");
        QCBORDecode_ExitMap(&auth_context);

        result = suit_qcbor_get_next(&auth_context, &item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s/ payload: / ", indent_space + indent_delta, "");
        if (item.uDataType == QCBOR_TYPE_NULL) {
            printf("null,\n");
        }
        else if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            suit_print_hex(item.val.string.ptr, item.val.string.len);
            printf("\n");
        }
        else {
            return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
        }

        result = suit_qcbor_get_next(&auth_context, &item, QCBOR_TYPE_BYTE_STRING);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s/ signature: / ", indent_space + indent_delta, "");
        suit_print_hex(item.val.string.ptr, item.val.string.len);

        QCBORError error = QCBORDecode_Finish(&auth_context);
        if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
            result = suit_error_from_qcbor_error(error);
        }
        printf("\n%*s])", indent_space, "");
    }
    return result;
}

suit_err_t suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space, const uint32_t indent_delta) {
    if (digest == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (digest->algorithm_id != SUIT_ALGORITHM_ID_INVALID
        && digest->bytes.len > 0) {
        printf("<< [\n");
        printf("%*s/ algorithm-id: / %d / %s /,\n", indent_space + indent_delta, "", digest->algorithm_id, suit_cose_alg_to_str(digest->algorithm_id));
        printf("%*s/ digest-bytes: / ", indent_space + indent_delta, "");
        result = suit_print_hex(digest->bytes.ptr, digest->bytes.len);
        printf("\n%*s] >>", indent_space, "");
    }
    return result;
}

int32_t suit_print_dependency(const suit_dependency_t *dependency, const uint32_t indent_space, const uint32_t indent_delta) {
    if (dependency == NULL) {
        return SUIT_ERR_FATAL;
    }
    int32_t result = SUIT_SUCCESS;
    if (dependency->digest.algorithm_id == SUIT_ALGORITHM_ID_INVALID) {
        return SUIT_ERR_FATAL;
    }

    printf("%*sdependency-digest : SUIT_Digest\n", indent_space, "");
    result = suit_print_digest(&dependency->digest, indent_space + indent_delta, indent_delta);
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

suit_err_t suit_print_text_component(const suit_text_component_t *text_component, const uint32_t indent_space, const uint32_t indent_delta) {
    if (text_component == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!suit_text_component_have_something_to_print(text_component)) {
        return SUIT_SUCCESS;
    }
    suit_err_t result = SUIT_SUCCESS;
    bool comma = false;
    if (text_component->vendor_name.ptr != NULL) {
        printf("%*s/ text-vendor-name / %d: ", indent_space, "", SUIT_TEXT_VENDOR_NAME);
        result = suit_print_string(&text_component->vendor_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->model_name.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-model-name / %d: ", indent_space, "", SUIT_TEXT_MODEL_NAME);
        result = suit_print_string(&text_component->model_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->vendor_domain.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-vendor-domain / %d: ", indent_space, "", SUIT_TEXT_VENDOR_DOMAIN);
        result = suit_print_string(&text_component->vendor_domain);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->model_info.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-model-info / %d: ", indent_space, "", SUIT_TEXT_MODEL_INFO);
        result = suit_print_string(&text_component->model_info);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->component_description.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-component-description / %d: ", indent_space, "", SUIT_TEXT_COMPONENT_DESCRIPTION);
        result = suit_print_string(&text_component->component_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->component_version.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-component-version / %d: ", indent_space, "", SUIT_TEXT_COMPONENT_VERSION);
        result = suit_print_string(&text_component->component_version);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->version_required.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*stext-version-required : ", indent_space, "");
        result = suit_print_string(&text_component->version_required);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
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

suit_err_t suit_print_text(const suit_text_t *text, const uint32_t indent_space, const uint32_t indent_delta) {
    if (text == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!suit_text_have_something_to_print(text)) {
        return SUIT_SUCCESS;
    }
    suit_err_t result = SUIT_SUCCESS;
    bool comma = false;
    if (text->manifest_description.ptr != NULL) {
        printf("%*s/ text-manifest-description / %d: ", indent_space + indent_delta, "", SUIT_TEXT_MANIFEST_DESCRIPTION);
        result = suit_print_string(&text->manifest_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text->update_description.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-update-description / %d: ", indent_space + indent_delta, "", SUIT_TEXT_UPDATE_DESCRIPTION);
        result = suit_print_string(&text->update_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text->manifest_json_source.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-manifest-json-source / %d: ", indent_space + indent_delta, "", SUIT_TEXT_MANIFEST_JSON_SOURCE);
        result = suit_print_string(&text->manifest_json_source);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text->manifest_yaml_source.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*stext-manifest-yaml-source : ", indent_space + indent_delta, "");
        result = suit_print_string(&text->manifest_yaml_source);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    for (size_t i = 0; i < text->component_len; i++) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s", indent_space + indent_delta, "");
        result = suit_print_component_identifier(&text->component[i].key);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf(": {\n");
        result = suit_print_text_component(&text->component[i].text_component, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n%*s}\n", indent_space + indent_delta, "");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_manifest(uint8_t mode, const suit_manifest_t *manifest, const uint32_t indent_space, const uint32_t indent_delta) {
    if (manifest == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    printf("%*s/ manifest(%s) / 3: << {\n", indent_space, "", suit_str_verified(manifest->is_verified));
    printf("%*s/ manifest-version / 1: %lu,\n", indent_space + indent_delta, "", manifest->version);
    printf("%*s/ manifest-sequence-number / 2: %lu,\n", indent_space + indent_delta, "", manifest->sequence_number);

    printf("%*s/ common / 3: << {\n", indent_space + indent_delta, "");
    bool comma = false;
    if (manifest->common.dependencies.len > 0) {
        printf("%*s/ dependencies / 1: [\n", indent_space + 2 * indent_delta, "");
        for (size_t i = 0; i < manifest->common.dependencies.len; i++) {
            result = suit_print_dependency(&manifest->common.dependencies.dependency[i], indent_space + 3 * indent_delta, indent_delta);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
        comma = true;
    }

    if (manifest->common.components.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ components / 2: [", indent_space + 2 * indent_delta, "");
        for (size_t i = 0; i < manifest->common.components.len; i++) {
            printf("\n%*s", indent_space + 3 * indent_delta, "");
            result = suit_print_component_identifier(&manifest->common.components.comp_id[i]);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            if (i + 1 != manifest->common.components.len) {
                printf(",");
            }
        }
        printf("\n%*s]", indent_space + 2 * indent_delta, "");
        comma = true;
    }
    if (manifest->common.cmd_seq.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ common-sequence / 4: << [\n", indent_space + 2 * indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->common.cmd_seq, indent_space + 3 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + 2 * indent_delta, "");
        comma = true;
    }
    printf("\n%*s} >>", indent_space + indent_delta, "");

    if (manifest->unsev_mem.validate.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ validate / 7: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.validate, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    if (manifest->unsev_mem.load.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ load / 8: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.load, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    if (manifest->unsev_mem.run.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ run / 9: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.run, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ dependency-resolution(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.dependency_resolution_status), SUIT_DEPENDENCY_RESOLUTION);
        result = suit_print_cmd_seq(mode, &manifest->sev_man_mem.dependency_resolution, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.dependency_resolution.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ dependency-resolution / %d: ", indent_space + indent_delta, "", SUIT_DEPENDENCY_RESOLUTION);
        result = suit_print_digest(&manifest->sev_mem_dig.dependency_resolution, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ payload-fetch(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.payload_fetch_status), SUIT_PAYLOAD_FETCH);
        result = suit_print_cmd_seq(mode, &manifest->sev_man_mem.payload_fetch, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.payload_fetch.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ payload-fetch / %d: ", indent_space + indent_delta, "", SUIT_PAYLOAD_FETCH);
        result = suit_print_digest(&manifest->sev_mem_dig.payload_fetch, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ install(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.install_status), SUIT_INSTALL);
        result = suit_print_cmd_seq(mode, &manifest->sev_man_mem.install, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.install.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ install / %d: ", indent_space + indent_delta, "", SUIT_INSTALL);
        result = suit_print_digest(&manifest->sev_mem_dig.install, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text(%s) / %d: << {\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.text_status), SUIT_TEXT);
        result = suit_print_text(&manifest->sev_man_mem.text, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s} >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.text.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text / %d: ", indent_space + indent_delta, "", SUIT_TEXT);
        result = suit_print_digest(&manifest->sev_mem_dig.text, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ coswid(%s) / %d: ", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.coswid_status), SUIT_COSWID);
        result = suit_print_hex(manifest->sev_man_mem.coswid.ptr, manifest->sev_man_mem.coswid.len);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    else if (manifest->sev_mem_dig.coswid.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*s/ coswid / %d: ", indent_space + indent_delta, "", SUIT_COSWID);
        result = suit_print_digest(&manifest->sev_mem_dig.coswid, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    printf("\n%*s} >>", indent_space, "");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_integrated_payload(uint8_t mode, const suit_payloads_t *payloads, const uint32_t indent_space, const uint32_t indent_delta) {
    for (size_t i = 0; i < payloads->len; i++) {
        printf("%*s\"%.*s\" : ", indent_space, "", (int)payloads->payload[i].key.len, (char *)payloads->payload[i].key.ptr);
        suit_print_hex(payloads->payload[i].bytes.ptr, payloads->payload[i].bytes.len);
        printf("\n");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_envelope(uint8_t mode, const suit_envelope_t *envelope, const uint32_t indent_space, const uint32_t indent_delta) {
    if (envelope == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    bool comma = false;
    printf("%*s/ SUIT_Envelope = /\n", indent_space, "");
    printf("%*s107({\n", indent_space, "");
    // authentication-wrapper
    printf("%*s/ authentication-wrapper / 2: << [\n", indent_space + indent_delta, "");
    printf("%*s/ digest: / ", indent_space + 2 * indent_delta, "");
    result = suit_print_digest(&envelope->wrapper.digest, indent_space + 2 * indent_delta, indent_delta);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    printf(",\n");
    for (size_t i = 0; i < envelope->wrapper.signatures_len; i++) {
        printf("%*s/ signature: / << ", indent_space + 2 * indent_delta, "");
        result = suit_print_signature(&envelope->wrapper.signatures[i], indent_space + 2 * indent_delta, indent_delta);
        printf(" >>\n");
    }
    printf("%*s] >>,\n", indent_space + indent_delta, "");

    // integrated-payload
    result = suit_print_integrated_payload(mode, &envelope->payloads, indent_space + indent_delta, indent_delta);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    // manifest
    result = suit_print_manifest(mode, &envelope->manifest, indent_space + indent_delta, indent_delta);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    comma = true;
    /* SUIT_Severable_Manifest_Members */
    if (envelope->manifest.sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ dependency-resolution(%s) / %d: << [\n", indent_space, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.dependency_resolution_status), SUIT_DEPENDENCY_RESOLUTION);
        result = suit_print_cmd_seq(mode, &envelope->manifest.sev_man_mem.dependency_resolution, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ payload-fetch(%s)/ %d: << [\n", indent_space, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.payload_fetch_status), SUIT_PAYLOAD_FETCH);
        result = suit_print_cmd_seq(mode, &envelope->manifest.sev_man_mem.payload_fetch, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.install_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ install(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.install_status), SUIT_INSTALL);
        result = suit_print_cmd_seq(mode, &envelope->manifest.sev_man_mem.install, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.text_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text(%s) / %d: << {\n", indent_space + indent_delta, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.text_status), SUIT_TEXT);
        result = suit_print_text(&envelope->manifest.sev_man_mem.text, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s} >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ coswid(%s) / %d: ", indent_space + indent_delta, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.coswid_status), SUIT_COSWID);
        result = suit_print_hex_in_max(envelope->manifest.sev_man_mem.coswid.ptr, envelope->manifest.sev_man_mem.coswid.len, SUIT_MAX_PRINT_BYTE_COUNT);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    // TODO: SUIT_Integrated_Payload, SUIT_Integrated_Dependency, $$SUIT_Envelope_Extensions
    // TODO: (int => bstr)

    printf("\n%*s})", indent_space, "");

    return SUIT_SUCCESS;
}

suit_err_t suit_print_run(suit_run_args_t run_args)
{
    printf("run callback : {\n");
    printf("  component-identifier : ");
    suit_print_component_identifier(&run_args.component_identifier);
    printf("\n");
    printf("  argument(len=%ld) : h'", run_args.args_len);
    suit_print_hex(run_args.args, run_args.args_len);
    printf("'\n");
    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", run_args.report.record_on_success, run_args.report.record_on_failure, run_args.report.sysinfo_success, run_args.report.sysinfo_failure);
    printf("}\n\n");
    return SUIT_SUCCESS;
}

suit_err_t suit_run_callback(suit_run_args_t run_args)
{
    return suit_print_run(run_args);
}

suit_err_t suit_print_copy(suit_copy_args_t copy_args)
{
    printf("copy args : {\n");
    printf("  src-component-identifier : ");
    suit_print_component_identifier(&copy_args.src);
    printf("\n");
    printf("  dst-component-identifier : ");
    suit_print_component_identifier(&copy_args.dst);
    printf("\n");

    printf("  copy-info : %s", suit_info_key_to_str(copy_args.info_key));
    switch (copy_args.info_key) {
    case SUIT_INFO_DEFAULT:
        /* nothing to be printed */
        break;
    case SUIT_INFO_ENCRYPTION:
        /* TODO: nothing to be printed */
        break;
    case SUIT_INFO_COMPRESSION:
        printf("{algorithm : %s}", suit_compression_algorithm_to_str(copy_args.info.compression.algorithm));
        break;
    case SUIT_INFO_UNPACK:
        printf("{algorithm : %s}", suit_unpack_algorithm_to_str(copy_args.info.unpack.algorithm));
        break;
    }
    printf("\n");

    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", copy_args.report.record_on_success, copy_args.report.record_on_failure, copy_args.report.sysinfo_success, copy_args.report.sysinfo_failure);
    printf("}\n\n");
    return SUIT_SUCCESS;
}

suit_err_t suit_copy_callback(suit_copy_args_t copy_args)
{
    return suit_print_copy(copy_args);
}

suit_err_t suit_print_store(suit_store_args_t store_args)
{
    suit_err_t ret = SUIT_SUCCESS;
    printf("store callback : {\n");
    switch (store_args.key) {
    case SUIT_DEPENDENCIES:
        printf("  dst-dependnecy-digest :\n");
        suit_print_digest(&store_args.dst.dependency.digest, 4, 4);
        printf("  dst-dependency-prefix : ");
        suit_print_component_identifier(&store_args.dst.dependency.prefix);
        printf("\n");
        break;
    case SUIT_COMPONENTS:
        printf("  dst-component-identifier : ");
        suit_print_component_identifier(&store_args.dst.component_identifier);
        printf("\n");
        break;
    default:
        printf("  dst-UNKNOWN(%d)\n", store_args.key);
        ret = SUIT_ERR_INVALID_KEY;
    }
    printf("  ptr : %p (%ld)\n", store_args.ptr, store_args.buf_len);
    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", store_args.report.record_on_success, store_args.report.record_on_failure, store_args.report.sysinfo_success, store_args.report.sysinfo_failure);
    printf("}\n\n");
    return ret;
}

suit_err_t suit_store_callback(suit_store_args_t store_args)
{
    return suit_print_store(store_args);
}

suit_err_t suit_print_fetch(suit_fetch_args_t fetch_args,
                            suit_fetch_ret_t *fetch_ret)
{
    suit_err_t ret = SUIT_SUCCESS;
    printf("fetch callback : {\n");
    int print_len = SUIT_MAX_PRINT_URI_COUNT;
    if (fetch_args.uri_len < print_len) {
        print_len = (int)fetch_args.uri_len;
    }
    printf("  uri : \"%.*s\"", print_len, (char *)fetch_args.uri);
    if (fetch_args.uri_len > SUIT_MAX_PRINT_URI_COUNT) {
        printf("...");
    }
    printf(" (%ld)\n", fetch_args.uri_len);
    switch (fetch_args.key) {
    case SUIT_DEPENDENCIES:
        printf("  dst-dependnecy-digest :\n");
        suit_print_digest(&fetch_args.dst.dependency.digest, 4, 4);
        printf("  dst-dependency-prefix : ");
        suit_print_component_identifier(&fetch_args.dst.dependency.prefix);
        printf("\n");
        break;
    case SUIT_COMPONENTS:
        printf("  dst-component-identifier : ");
        suit_print_component_identifier(&fetch_args.dst.component_identifier);
        printf("\n");
        break;
    default:
        printf("  dst-UNKNOWN(%d)\n", fetch_args.key);
        ret = SUIT_ERR_INVALID_KEY;
    }

    printf("  fetch buf : %p(%ld)\n", fetch_args.ptr, fetch_args.buf_len);
    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", fetch_args.report.record_on_success, fetch_args.report.record_on_failure, fetch_args.report.sysinfo_success, fetch_args.report.sysinfo_failure);
    printf("}\n\n");

    return ret;
}

suit_err_t suit_fetch_callback(suit_fetch_args_t fetch_args, suit_fetch_ret_t *fetch_ret)
{
    return suit_print_fetch(fetch_args, fetch_ret);
}

suit_err_t suit_print_report(suit_report_args_t report_args)
{
    printf("report callback : {\n");
    printf("  at: %d(%s)", report_args.level0, suit_envelope_key_to_str(report_args.level0));

    switch (report_args.level0) {
    case SUIT_AUTHENTICATION:
        break;
    case SUIT_MANIFEST:
        printf(", %d(%s)", report_args.level1.manifest_key, suit_manifest_key_to_str(report_args.level1.manifest_key));
        switch (report_args.level1.manifest_key) {
        case SUIT_COMMON:
            printf(", %d(%s)", report_args.level2.common_key, suit_common_key_to_str(report_args.level2.common_key));
            if (report_args.level2.common_key == SUIT_COMMON_SEQUENCE) {
                printf(", %d(%s)", report_args.level3.condition_directive, suit_command_sequence_key_to_str(report_args.level3.condition_directive));
                switch (report_args.level3.condition_directive) {
                case SUIT_DIRECTIVE_SET_PARAMETERS:
                case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                    printf(", %d(%s)", report_args.level4.parameter, suit_parameter_key_to_str(report_args.level4.parameter));
                    break;
                default:
                    break;
                }
            }
            break;
        case SUIT_INSTALL:
        case SUIT_VALIDATE:
        case SUIT_RUN:
            printf(", %d(%s)", report_args.level2.condition_directive, suit_command_sequence_key_to_str(report_args.level2.condition_directive));
            switch (report_args.level2.condition_directive) {
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                printf(", %d(%s)", report_args.level3.parameter, suit_parameter_key_to_str(report_args.level3.parameter));
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
        break;
    case SUIT_DELEGATION:
        break;
    default:
        break;
    }
    printf("\n");

    printf("  QCBORError:    %d(%s)\n", report_args.qcbor_error, qcbor_err_to_str(report_args.qcbor_error));
    printf("  suit_err_t:    %d(%s)\n", report_args.suit_error, suit_err_to_str(report_args.suit_error));
    printf("  suit_rep_policy_t: RecPass%x RecFail%x SysPass%x SysFail%x\n", report_args.report.record_on_success, report_args.report.record_on_failure, report_args.report.sysinfo_success, report_args.report.sysinfo_failure);

    printf("}\n\n");

    return SUIT_ERR_FATAL;
}

suit_err_t suit_report_callback(suit_report_args_t report_args)
{
    return suit_print_report(report_args);
}

