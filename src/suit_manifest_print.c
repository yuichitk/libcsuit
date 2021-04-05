/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "suit_common.h"
#include "suit_manifest_print.h"
#include <inttypes.h>

const char* SUIT_COMMAND_SEQUENCE_NUM_TO_STRING[] = {
    NULL,                               //SUIT_CONDITION_INVALID              = 0,
    "condition-vendor-identifier",      //SUIT_CONDITION_VENDOR_IDENTIFIER    = 1,
    "condition-class-identifier",       //SUIT_CONDITION_CLASS_IDENTIFIER     = 2,
    "condition-image-match",            //SUIT_CONDITION_IMAGE_MATCH          = 3,
    "condition-use-before",             //SUIT_CONDITION_USE_BEFORE           = 4,
    "condition-componetn-offset",       //SUIT_CONDITION_COMPONENT_OFFSET     = 5,
    NULL, NULL, NULL, NULL, NULL, NULL, //6, 7, 8, 9, 10, 11
    "directive-set-component-index",    //SUIT_DIRECTIVE_SET_COMPONENT_INDEX  = 12,
    "directive-set-dependency-index",   //SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX = 13,
    "condition-abort",                  //SUIT_CONDITION_ABORT                = 14,
    "directive-try-each",               //SUIT_DIRECTIVE_TRY_EACH             = 15,
    "directive-do-each",                //SUIT_DIRECTIVE_DO_EACH              = 16,
    "directive-map-filter",             //SUIT_DIRECTIVE_MAP_FILTER           = 17,
    "directive-process-dependency",     //SUIT_DIRECTIVE_PROCESS_DEPENDENCY   = 18,
    "directive-set-parameters",         //SUIT_DIRECTIVE_SET_PARAMETERS       = 19,
    "directive-override-parameters",    //SUIT_DIRECTIVE_OVERRIDE_PARAMETERS  = 20,
    "directive-fetch",                  //SUIT_DIRECTIVE_FETCH                = 21,
    "directive-copy",                   //SUIT_DIRECTIVE_COPY                 = 22,
    "directive-run",                    //SUIT_DIRECTIVE_RUN                  = 23,
    "condition-device-identifier",      //SUIT_CONDITION_DEVICE_IDENTIFIER    = 24,
    "condition-image-not-match",        //SUIT_CONDITION_IMAGE_NOT_MATCH      = 25,
    "condition-minimum-batterh",        //SUIT_CONDITION_MINIMUM_BATTERY      = 26,
    "condition-update-authorized",      //SUIT_CONDITION_UPDATE_AUTHORIZED    = 27,
    "condition-version",                //SUIT_CONDITION_VERSION              = 28,
    "directive-wait",                   //SUIT_DIRECTIVE_WAIT                 = 29,
    "directive-fetch-uri-list",         //SUIT_DIRECTIVE_FETCH_URI_LIST       = 30,
    "directive-swap",                   //SUIT_DIRECTIVE_SWAP                 = 31,
    "directive-run-sequence",           //SUIT_DIRECTIVE_RUN_SEQUENCE         = 32,
};

const char* SUIT_PARAMETER_NUM_TO_STRING[] = {
    NULL,                               //SUIT_PARAMETER_INVALID              = 0,
    "vendor-id",                        //SUIT_PARAMETER_VENDOR_IDENTIFIER    = 1,
    "class-id",                         //SUIT_PARAMETER_CLASS_IDENTIFIER     = 2,
    "image-digest",                     //SUIT_PARAMETER_IMAGE_DIGEST         = 3,
    "use-before",                       //SUIT_PARAMETER_USE_BEFORE           = 4,
    "component-offset",                 //SUIT_PARAMETER_COMPONENT_OFFSET     = 5,
    NULL, NULL, NULL, NULL, NULL, NULL, //6, 7, 8, 9, 10, 11,
    "strict-order",                     //SUIT_PARAMETER_STRICT_ORDER         = 12,
    "soft-failure",                     //SUIT_PARAMETER_SOFT_FAILURE         = 13,
    "image-size",                       //SUIT_PARAMETER_IMAGE_SIZE           = 14,
    NULL, NULL, NULL,                   //15, 16, 17
    "encryption-info",                  //SUIT_PARAMETER_ENCRYPTION_INFO      = 18,
    "compression-info",                 //SUIT_PARAMETER_COMPRESSION_INFO     = 19,
    "unpack-info",                      //SUIT_PARAMETER_UNPACK_INFO          = 20,
    "uri",                              //SUIT_PARAMETER_URI                  = 21,
    "source-component",                 //SUIT_PARAMETER_SOURCE_COMPONENT     = 22,
    "run-args",                         //SUIT_PARAMETER_RUN_ARGS             = 23,
    "device-identifier",                //SUIT_PARAMETER_DEVICE_IDENTIFIER    = 24,
    "minimum-battery",                  //SUIT_PARAMETER_MINIMUM_BATTERY      = 26,
    "update-priority",                  //SUIT_PARAMETER_UPDATE_PRIORITY      = 27,
    "version",                          //SUIT_PARAMETER_VERSION              = 28,
    "wait-info",                        //SUIT_PARAMETER_WAIT_INFO            = 29,
    "uri-list",                         //SUIT_PARAMETER_URI_LIST             = 30,
};

int32_t suit_print_string(const suit_buf_t *string) {
    if (string == NULL) {
        return SUIT_FATAL_ERROR;
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

int32_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space) {
    int32_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        printf("%*s%s : ", indent_space, "", SUIT_PARAMETER_NUM_TO_STRING[params_list->params[i].label]);
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
            case SUIT_PARAMETER_COMPONENT_OFFSET:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_COMPRESSION_INFO:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                printf("%" PRId64 "\n", params_list->params[i].value.uint64);
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
                result = SUIT_FATAL_ERROR;
                printf("?\n");
                break;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return SUIT_SUCCESS;
}

int32_t suit_print_cmd_seq(uint8_t mode, const suit_command_sequence_t *cmd_seq, const uint32_t indent_space) {
    int32_t result = SUIT_SUCCESS;
    suit_command_sequence_t tmp_cmd_seq;
    for (size_t i = 0; i < cmd_seq->len; i++) {
        printf("%*s%s : ", indent_space, "", SUIT_COMMAND_SEQUENCE_NUM_TO_STRING[cmd_seq->commands[i].label]);
        switch (cmd_seq->commands[i].label) {
            case SUIT_CONDITION_VENDOR_IDENTIFIER:
            case SUIT_CONDITION_CLASS_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_MATCH:
            case SUIT_CONDITION_COMPONENT_OFFSET:
            case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            case SUIT_DIRECTIVE_FETCH:
            case SUIT_DIRECTIVE_COPY:
            case SUIT_DIRECTIVE_RUN:
                printf("%" PRId64 "\n", cmd_seq->commands[i].value.uint64);
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

            case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
            case SUIT_DIRECTIVE_DO_EACH:
            case SUIT_DIRECTIVE_MAP_FILTER:
            case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
            case SUIT_DIRECTIVE_WAIT:
            case SUIT_DIRECTIVE_FETCH_URI_LIST:
            case SUIT_DIRECTIVE_SWAP:
            case SUIT_DIRECTIVE_RUN_SEQUENCE:
                result = SUIT_FATAL_ERROR;
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

int32_t suit_print_component_identifier(const suit_component_identifier_t *identifier) {
    if (identifier == NULL) {
        return SUIT_FATAL_ERROR;
    }
    printf("[");
    for (size_t j = 0; j < identifier->len; j++) {
        suit_print_hex_in_max(identifier->identifier[j].ptr, identifier->identifier[j].len, SUIT_MAX_PRINT_BYTE_COUNT);
    }
    printf("]");
    return SUIT_SUCCESS;
}

int32_t suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space) {
    if (digest == NULL) {
        return SUIT_FATAL_ERROR;
    }
    int32_t result = SUIT_SUCCESS;
    if (digest->algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*salgorithm-id : %u\n", indent_space, "", digest->algorithm_id);
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

bool suit_text_component_have_something_to_print(const suit_text_component_t *text_component) {
    return (text_component->vendor_name.ptr != NULL ||
            text_component->model_name.ptr != NULL ||
            text_component->vendor_domain.ptr != NULL ||
            text_component->model_info.ptr != NULL ||
            text_component->component_description.ptr != NULL ||
            text_component->component_version.ptr != NULL ||
            text_component->version_required.ptr != NULL);
}

int32_t suit_print_text_component(const suit_text_component_t *text_component, const uint32_t indent_space) {
    if (text_component == NULL) {
        return SUIT_FATAL_ERROR;
    }
    if (!suit_text_component_have_something_to_print(text_component)) {
        return SUIT_SUCCESS;
    }
    int32_t result = SUIT_SUCCESS;
    printf("%*stext :\n", indent_space, "");
    if (text_component->vendor_name.ptr != NULL) {
        printf("%*stext-vendor-name : ", indent_space + 2, "");
        result = suit_print_string(&text_component->vendor_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->model_name.ptr != NULL) {
        printf("%*stext-model-name : ", indent_space + 2, "");
        result = suit_print_string(&text_component->model_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->vendor_domain.ptr != NULL) {
        printf("%*stext-vendor-domain : ", indent_space + 2, "");
        result = suit_print_string(&text_component->vendor_domain);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->model_info.ptr != NULL) {
        printf("%*stext-vendor-info : ", indent_space + 2, "");
        result = suit_print_string(&text_component->model_info);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->component_description.ptr != NULL) {
        printf("%*stext-component-description : ", indent_space + 2, "");
        result = suit_print_string(&text_component->component_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    if (text_component->component_version.ptr != NULL) {
        printf("%*stext-component-version : ", indent_space + 2, "");
        result = suit_print_string(&text_component->component_version);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n");
    }
    if (text_component->version_required.ptr != NULL) {
        printf("%*stext-version-required : ", indent_space + 2, "");
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

int32_t suit_print_text(const suit_text_t *text, const uint8_t status, const uint32_t indent_space) {
    if (text == NULL) {
        return SUIT_FATAL_ERROR;
    }
    if (!suit_text_have_something_to_print(text)) {
        return SUIT_SUCCESS;
    }
    int32_t result = SUIT_SUCCESS;
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

int32_t suit_print_unseverable_members(uint8_t mode, const suit_unseverable_members_t *unsev_mem, uint32_t indent_space) {
    if (unsev_mem == NULL) {
        return SUIT_FATAL_ERROR;
    }
    int32_t result = SUIT_SUCCESS;
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

int32_t suit_print_severable_members_digests(const suit_severable_members_digests_t *sev_mem_dig, uint32_t indent_space) {
    if (sev_mem_dig == NULL) {
        return SUIT_FATAL_ERROR;
    }
    int32_t result = SUIT_SUCCESS;
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

int32_t suit_print_severable_manifest_members(uint8_t mode, const suit_severable_manifest_members_t *sev_man_mem, uint32_t indent_space, bool in_suit_manifest) {
    if (sev_man_mem == NULL) {
        return SUIT_FATAL_ERROR;
    }
    int32_t result = SUIT_SUCCESS;
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

int32_t suit_print_manifest(uint8_t mode, const suit_manifest_t *manifest, uint32_t indent_space) {
    if (manifest == NULL) {
        return SUIT_FATAL_ERROR;
    }
    int32_t result = SUIT_SUCCESS;
    printf("%*smanifest(%s) : SUIT_Manifest\n", indent_space, "", suit_str_verified(manifest->is_verified));
    printf("%*smanifest-version : %u\n", indent_space + 2, "", manifest->version);
    printf("%*smanifest-sequence-number : %u\n", indent_space + 2, "", manifest->sequence_number);

    printf("%*scommon : SUIT_Common\n", indent_space + 2, "");
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

int32_t suit_print_envelope(uint8_t mode, const suit_envelope_t *envelope, uint32_t indent_space) {
    if (envelope == NULL) {
        return SUIT_FATAL_ERROR;
    }
    int32_t result = SUIT_SUCCESS;
    printf("%*sSUIT Manifest Envelope :\n", indent_space, "");
    // authentication-wrapper
    if (envelope->wrapper.len > 0) {
        printf("%*sauthentication-wrapper : \n", indent_space + 2, "");
        printf("%*sdigest : SUIT_Digest \n", indent_space + 4, "");
        result = suit_print_digest(&envelope->wrapper.digest[0], indent_space + 6);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (envelope->wrapper.len > 0) {
            printf("%*ssignatures : [\n", indent_space + 4, "");
            for (size_t i = 1; i < envelope->wrapper.len; i++) {
                printf("%*sdigest(verified) : SUIT_Digest\n", indent_space + 6, "");
                result = suit_print_digest(&envelope->wrapper.digest[i], indent_space + 8);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
            }
            printf("%*s]\n", indent_space + 4, "");
        }
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
