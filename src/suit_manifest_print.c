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
        for (size_t j = 0; j < indent_space; j++) {
            putchar(' ');
        }
        printf("label %u : ", params_list->params[i].label);
        switch (params_list->params[i].label) {
            case 1:
            case 2:
            case 3:
                print_hex_in_max(params_list->params[i].value.string.ptr,
                                 params_list->params[i].value.string.len,
                                 MAX_PRINT_BYTE_COUNT);
                break;
            case 14:
                printf("%lu", params_list->params[i].value.uint64);
                break;
            case 21:
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
        for (size_t j = 0; j < indent_space; j++) {
            putchar(' ');
        }
        printf("label %u : ", cmd_seq->commands[i].label);
        switch (cmd_seq->commands[i].label) {
            case 1:
            case 2:
            case 3:
            case 21:
                if (cmd_seq->commands[i].value.isNull) {
                    printf("null\n");
                }
                break;
            case 19:
            case 20:
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

void suit_print_envelope(const suit_envelope_t *envelope) {
    printf("  SUIT Manifest Envelope :\n");
    // suit-authentication-wrapper
    if (envelope->wrapper.len > 0) {
        printf("    suit-authentication-wrapper : \n      ");
        for (size_t i = 0; i < envelope->wrapper.len; i++) {
            printf("No.%ld = ", i);
            print_hex_in_max(envelope->wrapper.auth_block[i].ptr,
                             envelope->wrapper.auth_block[i].len,
                             MAX_PRINT_BYTE_COUNT);
            printf(", ");
        }
    }
    printf("\n");
    // suit-manifest
    printf("    suit-manifest : \n");
    printf("      suit-manifest-version : %u\n", envelope->manifest.version);
    printf("      suit-manifest-sequence-number : %u\n", envelope->manifest.sequence_number);
    printf("      suit-common :\n");
    if (envelope->manifest.common.components.len > 0) {
        printf("        suit-components :\n");
        for (size_t i = 0; i < envelope->manifest.common.components.len; i++) {
            printf("          ");
            for (size_t j = 0; j < envelope->manifest.common.components.comp_id[i].len; j++) {
                printf("No.%ld-%ld = ", i, j);
                print_hex_in_max(envelope->manifest.common.components.comp_id[i].identifer[j].ptr,
                                 envelope->manifest.common.components.comp_id[i].identifer[j].len,
                                 MAX_PRINT_BYTE_COUNT);
                 printf(", ");
            }
            printf("\n");
        }
    }
    if (envelope->manifest.common.cmd_seq.len > 0) {
        printf("        suit-common-sequence :\n");
        suit_print_cmd_seq(&envelope->manifest.common.cmd_seq, 10);
    }
    if (envelope->manifest.install.value.cmd_seq.len > 0) {
        printf("      suit-install :\n");
        suit_print_cmd_seq(&envelope->manifest.install.value.cmd_seq, 8);
    }
    if (envelope->manifest.validate.len > 0) {
        printf("      suit-validate :\n");
        suit_print_cmd_seq(&envelope->manifest.validate, 8);
    }
    printf("\n");
}
