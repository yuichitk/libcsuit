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

void suit_print_string(const suit_buf_t *string) {
    size_t print_len = (string->len > MAX_PRINT_TEXT_COUNT) ? MAX_PRINT_TEXT_COUNT : string->len;
    printf("\"");
    for (size_t j = 0; j < print_len; j++) {
        putchar(string->ptr[j]);
    }
    printf("\"");
    if (string->len > print_len) {
        printf("..");
    }
}

void suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space) {
    for (size_t i = 0; i < params_list->len; i++) {
        printf("%*slabel %u : ", indent_space, "", params_list->params[i].label);
        switch (params_list->params[i].label) {
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
                suit_print_hex_in_max(params_list->params[i].value.string.ptr,
                                 params_list->params[i].value.string.len,
                                 MAX_PRINT_BYTE_COUNT);
                printf("\n");
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                printf("SUIT_Digest\n");
                suit_print_digest(&params_list->params[i].value.digest, indent_space + 2);
                break;
            case SUIT_PARAMETER_COMPONENT_OFFSET:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_COMPRESSION_INFO:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                printf("%lu\n", params_list->params[i].value.uint64);
                break;
            case SUIT_PARAMETER_URI:
                suit_print_string(&params_list->params[i].value.string);
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
                printf("?\n");
                break;
        }
    }
}

void suit_print_cmd_seq(const suit_command_sequence_t *cmd_seq, const uint32_t indent_space) {
    int32_t result;
    suit_command_sequence_t tmp_cmd_seq;
    for (size_t i = 0; i < cmd_seq->len; i++) {
        printf("%*slabel %u : ", indent_space, "", cmd_seq->commands[i].label);
        switch (cmd_seq->commands[i].label) {
            case SUIT_CONDITION_VENDOR_IDENTIFIER:
            case SUIT_CONDITION_CLASS_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_MATCH:
            case SUIT_CONDITION_COMPONENT_OFFSET:
            case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            case SUIT_DIRECTIVE_FETCH:
            case SUIT_DIRECTIVE_RUN:
                printf("%lu(0x%lx)\n", cmd_seq->commands[i].value.uint64, cmd_seq->commands[i].value.uint64);
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                if (cmd_seq->commands[i].value.params_list.len > 0) {
                    printf("SUIT_Parameters\n");
                    suit_print_suit_parameters_list(&cmd_seq->commands[i].value.params_list, indent_space + 2);
                }
                break;
            case SUIT_DIRECTIVE_TRY_EACH:
                //printf("parsing ");
                //suit_print_hex(cmd_seq->commands[i].value.string.ptr, cmd_seq->commands[i].value.string.len);
                printf("SUIT_Command_Sequence\n");
                result = suit_set_cmd_seq_from_buf(&cmd_seq->commands[i].value.string, &tmp_cmd_seq);
                if (result == SUIT_SUCCESS) {
                    suit_print_cmd_seq(&tmp_cmd_seq, indent_space + 2);
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
            case SUIT_DIRECTIVE_COPY:
            case SUIT_DIRECTIVE_WAIT:
            case SUIT_DIRECTIVE_FETCH_URI_LIST:
            case SUIT_DIRECTIVE_SWAP:
            case SUIT_DIRECTIVE_RUN_SEQUENCE:
                printf("?\n");
                break;
            default:
                break;
        }
    }
}

void suit_print_component_identifier(const suit_component_identifier_t *identifier) {
    printf("[ ");
    for (size_t j = 0; j < identifier->len; j++) {
        suit_print_hex_in_max(identifier->identifier[j].ptr, identifier->identifier[j].len, MAX_PRINT_BYTE_COUNT);
        printf(", ");
    }
    printf("]");
}

void suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space) {
    if (digest->algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*ssuit-digest-algorithm-id : %u\n", indent_space, "", digest->algorithm_id);
    }
    if (digest->bytes.len > 0) {
        printf("%*ssuit-digest-bytes : ", indent_space, "");
        suit_print_hex_in_max(digest->bytes.ptr, digest->bytes.len, MAX_PRINT_BYTE_COUNT);
        printf("\n");
    }
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

void suit_print_text_component(const suit_text_component_t *text_component, const uint32_t indent_space) {
    if (!suit_text_component_have_something_to_print(text_component)) {
        return;
    }
    printf("%*ssuit-text :\n", indent_space, "");
    if (text_component->vendor_name.ptr != NULL) {
        printf("%*ssuit-text-vendor-name : ", indent_space + 2, "");
        suit_print_string(&text_component->vendor_name);
        printf("\n");
    }
    if (text_component->model_name.ptr != NULL) {
        printf("%*ssuit-text-model-name : ", indent_space + 2, "");
        suit_print_string(&text_component->model_name);
        printf("\n");
    }
    if (text_component->vendor_domain.ptr != NULL) {
        printf("%*ssuit-text-vendor-domain : ", indent_space + 2, "");
        suit_print_string(&text_component->vendor_domain);
        printf("\n");
    }
    if (text_component->model_info.ptr != NULL) {
        printf("%*ssuit-text-vendor-info : ", indent_space + 2, "");
        suit_print_string(&text_component->model_info);
        printf("\n");
    }
    if (text_component->component_description.ptr != NULL) {
        printf("%*ssuit-text-component-description : ", indent_space + 2, "");
        suit_print_string(&text_component->component_description);
    }
    if (text_component->component_version.ptr != NULL) {
        printf("%*ssuit-text-component-version : ", indent_space + 2, "");
        suit_print_string(&text_component->component_version);
        printf("\n");
    }
    if (text_component->version_required.ptr != NULL) {
        printf("%*ssuit-text-version-required : ", indent_space + 2, "");
        suit_print_string(&text_component->version_required);
        printf("\n");
    }
}

bool suit_text_have_something_to_print(const suit_text_t *text) {
    return (text->manifest_description.ptr != NULL ||
            text->update_description.ptr != NULL ||
            text->manifest_json_source.ptr != NULL ||
            text->manifest_yaml_source.ptr != NULL ||
            text->component_len > 0);
}

void suit_print_text(const suit_text_t *text, const uint32_t indent_space) {
    if (!suit_text_have_something_to_print(text)) {
        return;
    }
    printf("%*ssuit-text : SUIT_Text_Map\n", indent_space, "");
    if (text->manifest_description.ptr != NULL) {
        printf("%*ssuit-text-manifest-description : ", indent_space + 2, "");
        suit_print_string(&text->manifest_description);
        printf("\n");
    }
    if (text->update_description.ptr != NULL) {
        printf("%*ssuit-text-update-description : ", indent_space + 2, "");
        suit_print_string(&text->update_description);
        printf("\n");
    }
    if (text->manifest_json_source.ptr != NULL) {
        printf("%*ssuit-text-manifest-json-source : ", indent_space + 2, "");
        suit_print_string(&text->manifest_json_source);
        printf("\n");
    }
    if (text->manifest_yaml_source.ptr != NULL) {
        printf("%*ssuit-text-manifest-yaml-source : ", indent_space + 2, "");
        suit_print_string(&text->manifest_yaml_source);
        printf("\n");
    }
    for (size_t i = 0; i < text->component_len; i++) {
        printf("%*s", indent_space + 2, "");
        suit_print_component_identifier(&text->component[i].key);
        printf(" :\n");
        suit_print_text_component(&text->component[i].text_component, indent_space + 4);
    }
}

void suit_print_unseverable_members(const suit_unseverable_members_t *unsev_mem, uint32_t indent_space) {
    if (unsev_mem->validate.len > 0) {
        printf("%*ssuit-validate : SUIT_Command_Sequence\n", indent_space + 2, "");
        suit_print_cmd_seq(&unsev_mem->validate, indent_space + 4);
    }
    if (unsev_mem->load.len > 0) {
        printf("%*ssuit-load : SUIT_Command_Sequence\n", indent_space + 2, "");
        suit_print_cmd_seq(&unsev_mem->load, indent_space + 4);
    }
    if (unsev_mem->run.len > 0) {
        printf("%*ssuit-run : SUIT_Command_Sequence\n", indent_space + 2, "");
        suit_print_cmd_seq(&unsev_mem->run, indent_space + 4);
    }
}

void suit_print_severable_members_digests(const suit_severable_members_digests_t *sev_mem_dig, uint32_t indent_space) {
    if (sev_mem_dig->dependency_resolution.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*ssuit-dependency-resolution : SUIT_Digest\n", indent_space, "");
        suit_print_digest(&sev_mem_dig->dependency_resolution, indent_space + 2);
    }
    if (sev_mem_dig->payload_fetch.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*ssuit-payload-fetch : SUIT_Digest\n", indent_space, "");
        suit_print_digest(&sev_mem_dig->payload_fetch, indent_space + 2);
    }
    if (sev_mem_dig->install.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*ssuit-install : SUIT_Digest\n", indent_space, "");
        suit_print_digest(&sev_mem_dig->install, indent_space + 2);
    }
    if (sev_mem_dig->text.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*ssuit-text : SUIT_Digest\n", indent_space, "");
        suit_print_digest(&sev_mem_dig->text, indent_space + 2);
    }
    if (sev_mem_dig->coswid.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*ssuit-coswid : SUIT_Digest\n", indent_space, "");
        suit_print_digest(&sev_mem_dig->coswid, indent_space + 2);
    }
}

void suit_print_severable_manifest_members(const suit_severable_manifest_members_t *sev_man_mem, uint32_t indent_space) {
    if (sev_man_mem->dependency_resolution.len > 0) {
        printf("%*ssuit-dependency-resolution : SUIT_Command_Sequence\n", indent_space, "");
        suit_print_cmd_seq(&sev_man_mem->dependency_resolution, indent_space + 2);
    }
    if (sev_man_mem->payload_fetch.len > 0) {
        printf("%*ssuit-payload-fetch : SUIT_Command_Sequence\n", indent_space, "");
        suit_print_cmd_seq(&sev_man_mem->payload_fetch, indent_space + 2);
    }
    if (sev_man_mem->install.len > 0) {
        printf("%*ssuit-install : SUIT_Command_Sequence\n", indent_space, "");
        suit_print_cmd_seq(&sev_man_mem->install, indent_space + 2);
    }
    suit_print_text(&sev_man_mem->text, indent_space);
    if (sev_man_mem->coswid.len > 0) {
        printf("%*ssuit-coswid : ", indent_space, "");
        suit_print_hex_in_max(sev_man_mem->coswid.ptr, sev_man_mem->coswid.len, MAX_PRINT_BYTE_COUNT);
        printf("\n");
    }
}

void suit_print_manifest(const suit_manifest_t *manifest, uint32_t indent_space) {
    // suit-manifest
    printf("%*ssuit-manifest : \n", indent_space, "");
    printf("%*ssuit-manifest-version : %u\n", indent_space + 2, "", manifest->version);
    printf("%*ssuit-manifest-sequence-number : %u\n", indent_space + 2, "", manifest->sequence_number);

    printf("%*ssuit-common :\n", indent_space + 2, "");
    if (manifest->common.components.len > 0) {
        printf("%*ssuit-components : [\n", indent_space + 4, "");
        for (size_t i = 0; i < manifest->common.components.len; i++) {
            printf("%*s", indent_space + 6, "");
            suit_print_component_identifier(&manifest->common.components.comp_id[i]);
            printf(",\n");
        }
        printf("%*s]\n", indent_space + 4, "");
    }
    if (manifest->common.cmd_seq.len > 0) {
        printf("%*ssuit-common-sequence :\n", indent_space + 4, "");
        suit_print_cmd_seq(&manifest->common.cmd_seq, indent_space + 6);
    }

    /* SUIT_Severable_Manifest_Members */
    suit_print_severable_manifest_members(&manifest->sev_man_mem, indent_space + 2);

    /* SUIT_Severable_Members_Digests */
    suit_print_severable_members_digests(&manifest->sev_mem_dig, indent_space + 2);

    /* SUIT_Unsevrable_Members */
    suit_print_unseverable_members(&manifest->unsev_mem, indent_space + 2);
}

void suit_print_envelope(const suit_envelope_t *envelope, uint32_t indent_space) {
    printf("%*sSUIT Manifest Envelope :\n", indent_space, "");
    // suit-authentication-wrapper
    if (envelope->wrapper.len > 0) {
        printf("%*ssuit-authentication-wrapper : \n", indent_space + 2, "");
        printf("%*ssuit-digest : \n", indent_space + 4, "");
        suit_print_digest(&envelope->wrapper.digest[0], indent_space + 6);
        for (size_t i = 1; i < envelope->wrapper.len; i++) {
            printf("%*ssuit-authentication-block(signed) : \n", indent_space + 4, "");
            suit_print_digest(&envelope->wrapper.digest[i], indent_space + 6);
        }
    }
    // suit-manifest
    suit_print_manifest(&envelope->manifest, indent_space + 2);

    /* SUIT_Severable_Manifest_Members */
    suit_print_severable_manifest_members(&envelope->sev_man_mem, indent_space + 2);

    // TODO: SUIT_Integrated_Payload, SUIT_Integrated_Dependency, $$SUIT_Envelope_Extensions
    // TODO: (int => bstr)
    printf("\n");
}
