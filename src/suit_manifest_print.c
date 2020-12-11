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

void suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space) {
    for (size_t i = 0; i < params_list->len; i++) {
        printf("%*slabel %u : ", indent_space, "", params_list->params[i].label);
        switch (params_list->params[i].label) {
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
            case SUIT_PARAMETER_IMAGE_DIGEST:
                suit_print_hex_in_max(params_list->params[i].value.string.ptr,
                                 params_list->params[i].value.string.len,
                                 MAX_PRINT_BYTE_COUNT);
                break;
            case SUIT_PARAMETER_IMAGE_SIZE:
                printf("%lu", params_list->params[i].value.uint64);
                break;
            case SUIT_PARAMETER_URI:
                for (size_t j = 0; j < params_list->params[i].value.string.len; j++) {
                    putchar(params_list->params[i].value.string.ptr[j]);
                }
                break;
            default:
                break;
        }
        printf("\n");
    }
}

void suit_print_cmd_seq(const suit_command_sequence_t *cmd_seq, const uint32_t indent_space) {
    for (size_t i = 0; i < cmd_seq->len; i++) {
        printf("%*slabel %u : ", indent_space, "", cmd_seq->commands[i].label);
        switch (cmd_seq->commands[i].label) {
            case SUIT_CONDITION_VENDOR_IDENTIFIER:
            case SUIT_CONDITION_CLASS_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_MATCH:
            case SUIT_DIRECTIVE_FETCH:
                printf("%lu(0x%lx)\n", cmd_seq->commands[i].value.uint64, cmd_seq->commands[i].value.uint64);
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                if (cmd_seq->commands[i].value.params_list.len > 0) {
                    printf("SUIT_Parameters\n");
                    suit_print_suit_parameters_list(&cmd_seq->commands[i].value.params_list, indent_space + 2);
                }
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
        printf("%*ssuit-digest-algorithm-id : %u,\n", indent_space, "", digest->algorithm_id);
    }
    if (digest->bytes.len > 0) {
        printf("%*ssuit-digest-bytes : ", indent_space, "");
        suit_print_hex_in_max(digest->bytes.ptr, digest->bytes.len, MAX_PRINT_BYTE_COUNT);
        printf("\n");
    }
}

void suit_print_envelope(const suit_envelope_t *envelope, uint32_t indent_space) {
    printf("%*sSUIT Manifest Envelope :\n", indent_space, "");
    // suit-authentication-wrapper
    if (envelope->wrapper.len > 0) {
        printf("%*ssuit-authentication-wrapper : \n", indent_space + 2, "");
        printf("%*ssuit-digest : \n", indent_space + 4, "");
        suit_print_digest(&envelope->wrapper.digest, indent_space + 6);
        for (size_t i = 1; i < envelope->wrapper.len; i++) {
            printf("%*ssuit-authentication-block No.%ld : ", indent_space + 4, "", i - 1);
            suit_print_hex_in_max(envelope->wrapper.auth_block[i - 1].ptr,
                             envelope->wrapper.auth_block[i - 1].len,
                             MAX_PRINT_BYTE_COUNT);
            printf(",\n");
        }
    }
    // suit-manifest
    printf("%*ssuit-manifest : \n", indent_space + 2, "");
    printf("%*ssuit-manifest-version : %u\n", indent_space + 4, "", envelope->manifest.version);
    printf("%*ssuit-manifest-sequence-number : %u\n", indent_space + 4, "", envelope->manifest.sequence_number);

    printf("%*ssuit-common :\n", indent_space + 4, "");
    if (envelope->manifest.common.components.len > 0) {
        printf("%*ssuit-components : [\n", indent_space + 6, "");
        for (size_t i = 0; i < envelope->manifest.common.components.len; i++) {
            printf("%*s", indent_space + 8, "");
            suit_print_component_identifier(&envelope->manifest.common.components.comp_id[i]);
            printf(",\n");
        }
        printf("%*s]\n", indent_space + 6, "");
    }
    if (envelope->manifest.common.cmd_seq.len > 0) {
        printf("%*ssuit-common-sequence :\n", indent_space + 6, "");
        suit_print_cmd_seq(&envelope->manifest.common.cmd_seq, indent_space + 8);
    }

    if (envelope->manifest.install.value.cmd_seq.len > 0) {
        printf("%*ssuit-install :\n", indent_space + 4, "");
        suit_print_cmd_seq(&envelope->manifest.install.value.cmd_seq, indent_space + 6);
    }
    if (envelope->manifest.validate.len > 0) {
        printf("%*ssuit-validate :\n", indent_space + 4, "");
        suit_print_cmd_seq(&envelope->manifest.validate, indent_space + 6);
    }
    printf("\n");
}
