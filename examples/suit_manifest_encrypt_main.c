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
#include "trust_anchor_hmac256.h"

#define MAX_FILE_BUFFER_SIZE            2048

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 1) {
        printf("%s [<output manifest file path>]", argv[0]);
        return EXIT_FAILURE;
    }
    char *manifest_file = (argc >= 1) ? argv[1] : NULL;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM] = {0};

    const unsigned char *secret_key = trust_anchor_hmac256_secret_key;

    // Set MAC0 key
    suit_err_t result = suit_key_init_hmac_256(secret_key, &mechanisms[0].key);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to create HMAC256 secret key. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanisms[0].cose_tag = CBOR_TAG_COSE_MAC0;
    mechanisms[0].use = true;

    // Prepare
    uint8_t encrypted_payload_buf[] = {
        0x4A, 0x22, 0x9F, 0x5C, 0x3B, 0xE5, 0xBF, 0x7B,
        0x72, 0x3C, 0x78, 0x35, 0x89, 0xA6, 0x22, 0x5C,
        0x2C, 0xD1, 0xC0, 0xAF, 0xB8, 0xD5, 0x0B, 0x9C,
        0x40, 0x67, 0x64, 0xD6, 0x84, 0xE3, 0x8C, 0xD4,
        0x59, 0x5F, 0x52, 0x6C, 0xEB, 0xFB, 0xFF, 0x11,
        0x9C, 0xE4
    };
    UsefulBufC encrypted_payload = {.ptr = encrypted_payload_buf, .len = sizeof(encrypted_payload_buf)};

    /*
    96(
        [
            / protected field with alg=AES-GCM-128 /
            h'A10101',
            {
               / unprotected field with iv /
               5: h'26682306D4FB28CA01B43B80'
            },
            / null because of detached ciphertext /
            null,
            [ / recipients array /
               h'', / protected field /
               {    / unprotected field /
                  1: -3,            / alg=A128KW /
                  4: h'6B69642D31'  / key id /
               },
               / CEK encrypted with KEK /
               h'AF09622B4F40F17930129D18D0CEA46F159C49E7F68B644D'
            ]
        ]
    )
    */
    uint8_t encryption_info_buf[] = {
        0xD8, 0x60, 0x84, 0x43, 0xA1, 0x01, 0x01, 0xA1,
        0x05, 0x4C, 0x26, 0x68, 0x23, 0x06, 0xD4, 0xFB,
        0x28, 0xCA, 0x01, 0xB4, 0x3B, 0x80, 0xF6, 0x83,
        0x40, 0xA2, 0x01, 0x22, 0x04, 0x45, 0x6B, 0x69,
        0x64, 0x2D, 0x31, 0x58, 0x18, 0xAF, 0x09, 0x62,
        0x2B, 0x4F, 0x40, 0xF1, 0x79, 0x30, 0x12, 0x9D,
        0x18, 0xD0, 0xCE, 0xA4, 0x6F, 0x15, 0x9C, 0x49,
        0xE7, 0xF6, 0x8B, 0x64, 0x4D
    };
    UsefulBufC encryption_info = {
        .ptr = encryption_info_buf,
        .len = sizeof(encryption_info_buf)
    };

    // Generate manifest
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    envelope.tagged = true;
    suit_manifest_t *manifest = &envelope.manifest;
    manifest->version = 1;
    manifest->sequence_number = 0;

    char uri[] = "https://author.example.com/encrypted-firmware.bin";

    /* Encrypted firmware */
    uint8_t component_id_0[] = {0x00};
    /* Decrypted firmware */
    uint8_t component_id_1[] = {0x01};
    suit_common_t *common = &manifest->common;
    common->components.len = 2;
    common->components.comp_id[0].len = 1;
    common->components.comp_id[0].identifier[0] = (suit_buf_t){.ptr = component_id_0, .len = sizeof(component_id_0)};
    common->components.comp_id[1].len = 1;
    common->components.comp_id[1].identifier[0] = (suit_buf_t){.ptr = component_id_1, .len = sizeof(component_id_1)};


    uint8_t vendor_id[] = {0xC0, 0xDD, 0xD5, 0xF1, 0x52, 0x43, 0x56, 0x60, 0x87, 0xDB, 0x4F, 0x5B, 0x0A, 0xA2, 0x6C, 0x2F};
    uint8_t class_id[] = {0xDB, 0x42, 0xF7, 0x09, 0x3D, 0x8C, 0x55, 0xBA, 0xA8, 0xC5, 0x26, 0x5F, 0xC5, 0x82, 0x0F, 0x4E};
    suit_command_sequence_t *cmd_seq = &common->shared_seq;
    cmd_seq->len = 4;

    suit_parameters_list_t *params_list;
    cmd_seq->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    cmd_seq->commands[0].value.int64 = 0;
    cmd_seq->commands[1].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &cmd_seq->commands[1].value.params_list;
    params_list->len = 3;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    params_list->params[2].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[2].value.uint64 = encrypted_payload.len;

    cmd_seq->commands[2].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15; // report all

    cmd_seq->commands[3].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[3].value.uint64 = 15; // report all

    /* install */
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 6;
    install->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    install->commands[0].value.int64 = 1; /* Encrypted firmware */
    install->commands[1].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &install->commands[1].value.params_list;
    params_list->len = 1;

    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = (const void *)uri;
    params_list->params[0].value.string.len = strlen(uri);

    install->commands[2].label = SUIT_DIRECTIVE_FETCH;
    install->commands[2].value.uint64 = 15;

    install->commands[3].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    install->commands[3].value.int64 = 0; /* Decrypted firmware */
    install->commands[4].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &install->commands[4].value.params_list;
    params_list->len = 2;

    params_list->params[0].label = SUIT_PARAMETER_SOURCE_COMPONENT;
    params_list->params[0].value.uint64 = 1; /* Encrypted firmware */
    params_list->params[1].label = SUIT_PARAMETER_ENCRYPTION_INFO;
    params_list->params[1].value.string.ptr = encryption_info.ptr;
    params_list->params[1].value.string.len = encryption_info.len;

    install->commands[5].label = SUIT_DIRECTIVE_COPY;
    install->commands[5].value.uint64 = 15;

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
    result = suit_print_envelope(mode, &envelope, 4, 2);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to print Manifest file.\n");
        return EXIT_FAILURE;
    }

    // Encode manifest.
    uint8_t encode_buf[MAX_FILE_BUFFER_SIZE];
    size_t encode_len = MAX_FILE_BUFFER_SIZE;
    uint8_t *ret_pos = encode_buf;
    printf("\nmain : Encode Manifest.\n");
    result = suit_encode_envelope(mode, &envelope, mechanisms, &ret_pos, &encode_len);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to encode. %d\n", result);
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
