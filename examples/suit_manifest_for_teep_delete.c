/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "qcbor/qcbor.h"
#include "csuit/suit_manifest_data.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_digest.h"
#include "suit_examples_common.h"
#include "trust_anchor_prime256v1.h"
#include "trust_anchor_prime256v1_pub.h"

#define MAX_FILE_BUFFER_SIZE            2048

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 1) {
        printf("%s [<output manifest file path>]", argv[0]);
        return EXIT_FAILURE;
    }
    char *manifest_file = (argc >= 1) ? argv[1] : NULL;

    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
    const unsigned char *public_key = trust_anchor_prime256v1_public_key;
    const unsigned char *private_key = trust_anchor_prime256v1_private_key;
    suit_err_t result = suit_key_init_es256_key_pair(private_key, public_key, &mechanisms[0].key);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to create ES256 key pair. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanisms[0].cose_tag = CBOR_TAG_COSE_SIGN1;
    mechanisms[0].use = true;

    // Generate manifest
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_manifest_t *manifest = &envelope.manifest;
    manifest->version = 1;
    manifest->sequence_number = UINT64_MAX;

    /* "TEEP-Device" */
    uint8_t component_id_0[] = {0x54, 0x45, 0x45, 0x50, 0x2D, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65};
    /* "SecureFS" */
    uint8_t component_id_1[] = {0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x46, 0x53};
    /* UUID(8d82573a-926d-4754-9353-32dc29997f74) */
    uint8_t component_id_2[] = {0x8D, 0x82, 0x57, 0x3A, 0x92, 0x6D, 0x47, 0x54, 0x93, 0x53, 0x32, 0xDC, 0x29, 0x99, 0x7F, 0x74};
    /* "ta" */
    uint8_t component_id_3[] = {0x74, 0x61};
    suit_common_t *common = &manifest->common;
    common->components.len = 1;
    common->components.comp_id[0].len = 4;
    common->components.comp_id[0].identifier[0] = (suit_buf_t){.ptr = component_id_0, .len = sizeof(component_id_0)};
    common->components.comp_id[0].identifier[1] = (suit_buf_t){.ptr = component_id_1, .len = sizeof(component_id_1)};
    common->components.comp_id[0].identifier[2] = (suit_buf_t){.ptr = component_id_2, .len = sizeof(component_id_2)};
    common->components.comp_id[0].identifier[3] = (suit_buf_t){.ptr = component_id_3, .len = sizeof(component_id_3)};


    uint8_t vendor_id[] = {0xC0, 0xDD, 0xD5, 0xF1, 0x52, 0x43, 0x56, 0x60, 0x87, 0xDB, 0x4F, 0x5B, 0x0A, 0xA2, 0x6C, 0x2F};
    uint8_t class_id[] = {0xDB, 0x42, 0xF7, 0x09, 0x3D, 0x8C, 0x55, 0xBA, 0xA8, 0xC5, 0x26, 0x5F, 0xC5, 0x82, 0x0F, 0x4E};
    suit_command_sequence_t *cmd_seq = &common->cmd_seq;
    cmd_seq->len = 3;

    suit_parameters_list_t *params_list;
    cmd_seq->commands[0].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &cmd_seq->commands[0].value.params_list;
    params_list->len = 2;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    cmd_seq->commands[1].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[1].value.uint64 = 15; // report all

    cmd_seq->commands[2].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15; // report all

    /* install */
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 2;
    install->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    install->commands[0].value.uint64 = 0;

    install->commands[1].label = SUIT_DIRECTIVE_UNLINK;
    install->commands[1].value.uint64 = 0;


    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
    result = suit_print_envelope(mode, &envelope, 4, 2);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to print Manifest file. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Encode manifest.
    uint8_t encode_buf[MAX_FILE_BUFFER_SIZE];
    size_t encode_len = MAX_FILE_BUFFER_SIZE;
    uint8_t *ret_pos = encode_buf;
    printf("\nmain : Encode Manifest.\n");
    result = suit_encode_envelope(mode, &envelope, mechanisms, &ret_pos, &encode_len);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to encode. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    if (manifest_file != NULL) {
        size_t w_len = write_to_file(manifest_file, encode_len, ret_pos);
        if (w_len != encode_len) {
            printf("main : Failed to write to %s\n", manifest_file);
        }
    }
    else {
        printf("main : Skip to write to a file (dry-run).\n");
    }

    suit_free_key(&mechanisms[0].key);
    return EXIT_SUCCESS;
}
