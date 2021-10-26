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

#define MAX_FILE_BUFFER_SIZE            2048

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 1) {
        printf("%s <private key path> [<output manifest file path>]", argv[0]);
        return EXIT_FAILURE;
    }
    char *private_key_file = argv[1];
    char *manifest_file = (argc >= 2) ? argv[2] : NULL;
    struct t_cose_key key_pair;
    char public_key[PRIME256V1_PUBLIC_KEY_CHAR_SIZE + 1];
    char private_key[PRIME256V1_PRIVATE_KEY_CHAR_SIZE + 1];

    // Read der file.
    printf("\nmain : Read Private&Public Key.\n");
    uint8_t der_buf[PRIME256V1_PRIVATE_KEY_DER_SIZE];
    size_t der_len = read_from_file(private_key_file, PRIME256V1_PRIVATE_KEY_DER_SIZE, der_buf);
    if (!der_len) {
        printf("main : Can't read DER file.\n");
        return EXIT_FAILURE;
    }
    suit_print_hex(der_buf, der_len);
    printf("\n");

    // Read key pair from der file.
    read_prime256v1_key_pair(der_buf, private_key, public_key);
    printf("Private Key : %s\n", private_key);
    printf("Public Key : %s\n", public_key);
    int32_t result = suit_create_es256_key_pair(private_key, public_key, &key_pair);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't create ES256 key pair.\n");
        return EXIT_FAILURE;
    }

    // Generate manifest
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_manifest_t *manifest = &envelope.manifest;
    manifest->version = 1;
    manifest->sequence_number = 3;

    char trusted_component[] = "Hello, Secure World!";
    UsefulBufC payload = {.ptr = trusted_component, .len = strlen(trusted_component)};
    envelope.payloads.len = 0;
    char uri[] = "https://tc.org/8d82573a-926d-4754-9353-32dc29997f74.ta";
    envelope.payloads.payload[0].key = (UsefulBufC){.ptr = (const void *)uri, .len = strlen(uri)};
    envelope.payloads.payload[0].bytes = payload;

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
    params_list->len = 4;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    suit_digest_t image_digest;
    image_digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    image_digest.bytes.ptr = hash;
    image_digest.bytes.len = sizeof(hash);
    result = suit_generate_digest(payload.ptr, payload.len, &image_digest);
    params_list->params[2].label = SUIT_PARAMETER_IMAGE_DIGEST,
    params_list->params[2].value.digest = image_digest;;

    params_list->params[3].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[3].value.uint64 = payload.len;

    cmd_seq->commands[1].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[1].value.uint64 = 15; // report all

    cmd_seq->commands[2].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15; // report all

    /* install */
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 3;
    install->commands[0].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;

    params_list = &install->commands[0].value.params_list;
    params_list->len = 1;

    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = (const void *)uri;
    params_list->params[0].value.string.len = strlen(uri);

    install->commands[1].label = SUIT_DIRECTIVE_FETCH;
    install->commands[1].value.uint64 = 15;

    install->commands[2].label = SUIT_CONDITION_IMAGE_MATCH;
    install->commands[2].value.uint64 = 15;

    /* text */
    manifest->sev_man_mem.text_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_text_t *text = &manifest->sev_man_mem.text;
    text->component_len = 1;
    text->component[0].key = common->components.comp_id[0];
    const char model_name[] = "Reference TEEP-Device";
    const char vendor_domain[] = "tc.org";
    text->component[0].text_component.model_name = (suit_buf_t){.ptr = (const uint8_t *)model_name, .len = strlen(model_name)};
    text->component[0].text_component.vendor_domain = (suit_buf_t){.ptr = (const uint8_t *)vendor_domain, .len = strlen(vendor_domain)};


    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
    result = suit_print_envelope(mode, &envelope, 2);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't print Manifest file.\n");
        return EXIT_FAILURE;
    }

    // Encode manifest.
    uint8_t encode_buf[MAX_FILE_BUFFER_SIZE];
    size_t encode_len = MAX_FILE_BUFFER_SIZE;
    printf("\nmain : Encode Manifest.\n");
    result = suit_encode_envelope(mode, &envelope, &key_pair, encode_buf, &encode_len);
    if (result != SUIT_SUCCESS) {
        printf("main : Fail to encode. %d\n", result);
        return EXIT_FAILURE;
    }

    if (manifest_file != NULL) {
        size_t w_len = write_to_file(manifest_file, encode_len, encode_buf);
        if (w_len != encode_len) {
            printf("main : Fail to write to %s\n", manifest_file);
        }
    }
    else {
        printf("main : Skip to write to a file (dry-run).\n");
    }

    return EXIT_SUCCESS;
}
