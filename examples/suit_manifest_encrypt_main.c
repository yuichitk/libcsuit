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
    suit_mechanism_t mechanism = {.cose_tag = CBOR_TAG_COSE_SIGN1};
    const unsigned char *public_key = trust_anchor_prime256v1_public_key;
    const unsigned char *private_key = trust_anchor_prime256v1_private_key;

    // Read key pair from der file.
    suit_err_t result = suit_key_init_es256_key_pair(private_key, public_key, &mechanism.keys[0]);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to create ES256 key pair. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Prepare
    char true_payload_buf[] = "This is a real firmware image.";
    UsefulBufC true_payload = {.ptr = true_payload_buf, .len = strlen(true_payload_buf)};
    uint8_t true_payload_hash[SHA256_DIGEST_WORK_SPACE_LENGTH];
    suit_digest_t true_payload_digest;
    true_payload_digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    result = suit_generate_sha256(true_payload.ptr, true_payload.len, true_payload_hash, sizeof(true_payload_hash));
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to generate sha256 hash. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    true_payload_digest.bytes.ptr = true_payload_hash;
    true_payload_digest.bytes.len = SHA256_DIGEST_LENGTH;

    uint8_t encrypted_payload_buf[] = {
        0x4A, 0x22, 0x9F, 0x5C, 0x3B, 0xE5, 0xBF, 0x7B,
        0x72, 0x3C, 0x78, 0x35, 0x89, 0xA6, 0x22, 0x5C,
        0x2C, 0xD1, 0xC0, 0xAF, 0xB8, 0xD5, 0x0B, 0x9C,
        0x40, 0x67, 0x64, 0xD6, 0x84, 0xE3, 0x8C, 0xD4,
        0x59, 0x5F, 0x52, 0x6C, 0xEB, 0xFB, 0xFF, 0x11,
        0x9C, 0xE4
    };
    UsefulBufC encrypted_payload = {.ptr = encrypted_payload_buf, .len = sizeof(encrypted_payload_buf)};
    uint8_t encrypted_payload_hash[SHA256_DIGEST_WORK_SPACE_LENGTH];
    suit_digest_t encrypted_payload_digest;
    encrypted_payload_digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    result = suit_generate_sha256(encrypted_payload.ptr, encrypted_payload.len, encrypted_payload_hash, sizeof(encrypted_payload_hash));
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to generate sha256 hash. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    encrypted_payload_digest.bytes.ptr = encrypted_payload_hash;
    encrypted_payload_digest.bytes.len = SHA256_DIGEST_LENGTH;

    uint8_t encryption_info_buf[] = {
        0xD8, 0x60, 0x84, 0x43, 0xA1, 0x01, 0x01, 0xA1,
        0x05, 0x50, 0xE0, 0x16, 0xC2, 0x8F, 0xF8, 0x35,
        0x0E, 0xF0, 0xAD, 0x9A, 0xD0, 0x02, 0x85, 0x35,
        0xEF, 0x01, 0xF6, 0x83, 0x44, 0xA1, 0x01, 0x38,
        0x63, 0xA2, 0x20, 0x58, 0x4B, 0xA4, 0x01, 0x02,
        0x20, 0x01, 0x21, 0x58, 0x20, 0xE9, 0x80, 0x86,
        0xD0, 0x70, 0x84, 0x1A, 0x55, 0xDC, 0x4C, 0xA2,
        0x9E, 0xD7, 0x39, 0x86, 0xBD, 0x4D, 0x8A, 0xF4,
        0x5F, 0x0A, 0xA5, 0x5A, 0xF9, 0x22, 0xE6, 0x21,
        0x12, 0xE7, 0x3D, 0xD0, 0x51, 0x22, 0x58, 0x20,
        0xC7, 0x2B, 0xEF, 0x9D, 0xD5, 0xF3, 0x88, 0xA9,
        0x0F, 0x9F, 0x02, 0xDF, 0x48, 0x4F, 0x7E, 0xD8,
        0x17, 0x44, 0x97, 0xAC, 0x6E, 0x83, 0x04, 0x2C,
        0x24, 0x08, 0x48, 0x48, 0x3B, 0x7F, 0xA8, 0xD0,
        0x04, 0x45, 0x6B, 0x69, 0x64, 0x2D, 0x32, 0x58,
        0x20, 0x37, 0x42, 0xF8, 0x4B, 0x10, 0xA6, 0xE5,
        0x6B, 0xE9, 0x2F, 0xDB, 0xEE, 0xF2, 0x65, 0x0D,
        0x2A, 0x63, 0x61, 0x7D, 0xA4, 0x12, 0xF2, 0xA7,
        0xA7, 0xE8, 0xE7, 0x82, 0x7F, 0xC0, 0x46, 0xFA,
        0x50
    };
    UsefulBufC encryption_info = {
        .ptr = encryption_info_buf,
        .len = sizeof(encryption_info_buf)
    };

    // Generate manifest
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_manifest_t *manifest = &envelope.manifest;
    manifest->version = 1;
    manifest->sequence_number = 0;

    envelope.payloads.len = 1;
    char uri[] = "#encrypted-firmware";
    envelope.payloads.payload[0].key = (UsefulBufC){.ptr = (const void *)uri, .len = strlen(uri)};
    envelope.payloads.payload[0].bytes = encrypted_payload;

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
    suit_command_sequence_t *cmd_seq = &common->cmd_seq;
    cmd_seq->len = 4;

    suit_parameters_list_t *params_list;
    cmd_seq->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    cmd_seq->commands[0].value.int64 = 0;
    cmd_seq->commands[1].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &cmd_seq->commands[1].value.params_list;
    params_list->len = 4;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    params_list->params[2].label = SUIT_PARAMETER_IMAGE_DIGEST,
    params_list->params[2].value.digest = encrypted_payload_digest;

    params_list->params[3].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[3].value.uint64 = encrypted_payload.len;

    cmd_seq->commands[2].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15; // report all

    cmd_seq->commands[3].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[3].value.uint64 = 15; // report all

    /* validate */
    suit_command_sequence_t *validate = &manifest->unsev_mem.validate;
    validate->len = 2;
    validate->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    validate->commands[0].value.int64 = 0;
    validate->commands[1].label = SUIT_CONDITION_IMAGE_MATCH;
    validate->commands[1].value.uint64 = 15; // report all

    /* install */
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 4;
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

    install->commands[3].label = SUIT_CONDITION_IMAGE_MATCH;
    install->commands[3].value.uint64 = 15;

    /* load */
    suit_command_sequence_t *load = &manifest->unsev_mem.load;
    load->len = 4;
    load->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    load->commands[0].value.int64 = 0; /* Decrypted firmware */
    load->commands[1].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &load->commands[1].value.params_list;
    params_list->len = 4;

    params_list->params[0].label = SUIT_PARAMETER_IMAGE_DIGEST;
    params_list->params[0].value.digest = true_payload_digest;
    params_list->params[1].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[1].value.uint64 = true_payload.len;
    params_list->params[2].label = SUIT_PARAMETER_SOURCE_COMPONENT;
    params_list->params[2].value.uint64 = 1; /* Encrypted firmware */
    params_list->params[3].label = SUIT_PARAMETER_ENCRYPTION_INFO;
    params_list->params[3].value.string.ptr = encryption_info.ptr;
    params_list->params[3].value.string.len = encryption_info.len;

    load->commands[2].label = SUIT_DIRECTIVE_COPY;
    load->commands[2].value.uint64 = 2;
    load->commands[3].label = SUIT_CONDITION_IMAGE_MATCH;
    load->commands[3].value.uint64 = 15;

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
    result = suit_print_envelope(mode, &envelope, 4, 4);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to print Manifest file.\n");
        return EXIT_FAILURE;
    }

    // Encode manifest.
    uint8_t encode_buf[MAX_FILE_BUFFER_SIZE];
    size_t encode_len = MAX_FILE_BUFFER_SIZE;
    uint8_t *ret_pos = encode_buf;
    printf("\nmain : Encode Manifest.\n");
    result = suit_encode_envelope(mode, &envelope, &mechanism, &ret_pos, &encode_len);
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

    suit_free_key(&mechanism.keys[0]);
    return EXIT_SUCCESS;
}
