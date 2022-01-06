/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <unistd.h>
#include "qcbor/qcbor.h"
#include "csuit/suit_manifest_data.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_digest.h"
#include "suit_examples_common.h"

#define MAX_FILE_BUFFER_SIZE            2048

int error_print(char *argv0) {
    printf("%s <manifest to depend> <private key path> [-u <manifest uri>] [-o <output manifest file path>]", argv0);
    return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
    // check arguments.
    int c;
    extern char *optarg;
    extern int optind, optopt;

    char *input_manifest_file = NULL;
    char *uri = NULL;
    char *private_key_file = NULL;
    char *output_manifest_file = NULL;

    while ((c = getopt(argc, argv, "u:o:")) != -1) {
        switch (c) {
        case 'u':
            uri = optarg;
            break;
        case 'o':
            output_manifest_file = optarg;
            break;
        case ':':
            printf("Option -%c requires an operand\n", optopt);
            return error_print(argv[0]);
            break;
        case '?':
            printf("Unrecognised option: -%c\n", optopt);
            return error_print(argv[0]);
        }
    }
    if (argc < optind + 2) {
        return error_print(argv[0]);
    }
    input_manifest_file = argv[optind];
    private_key_file = argv[optind + 1];

    struct t_cose_key key_pair;
    char public_key[PRIME256V1_PUBLIC_KEY_CHAR_SIZE + 1];
    char private_key[PRIME256V1_PRIVATE_KEY_CHAR_SIZE + 1];

    // Read a SUIT manifest to depend
    printf("\nmain : Read Manifest file to depend.\n");
    uint8_t manifest_buf[MAX_FILE_BUFFER_SIZE];
    size_t manifest_len = read_from_file(input_manifest_file, MAX_FILE_BUFFER_SIZE, manifest_buf);
    if (!manifest_len) {
        printf("main : Can't read Manifest file.\n");
        return EXIT_FAILURE;
    }
    suit_print_hex(manifest_buf, manifest_len);
    printf("\n");

    // Decode manifest file.
    printf("\nmain : Decode Manifest file.\n");
    uint8_t mode = SUIT_DECODE_MODE_SKIP_ANY_ERROR;
    suit_envelope_t read_envelope = (suit_envelope_t){ 0 };
    suit_buf_t buf = {.ptr = manifest_buf, .len = manifest_len};
    t_cose_key cose_key = {0}; // fake key

    int32_t result = suit_decode_envelope(mode, &buf, &read_envelope, &cose_key);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't parse Manifest file. err=%d\n", result);
        return EXIT_FAILURE;
    }

    suit_digest_t *digest = &read_envelope.wrapper.digest;

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
    result = suit_create_es256_key_pair(private_key, public_key, &key_pair);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't create ES256 key pair.\n");
        return EXIT_FAILURE;
    }

    // Generate manifest
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_manifest_t *manifest = &envelope.manifest;
    manifest->version = 1;
    manifest->sequence_number = 3;

    char integrated_uri[] = "#depending";
    if (uri == NULL) {
        envelope.payloads.len = 1;
        envelope.payloads.payload[0].key = (UsefulBufC){.ptr = (const void *)integrated_uri, .len = strlen(integrated_uri)};
        envelope.payloads.payload[0].bytes = (UsefulBufC){.ptr = (const void *)manifest_buf, .len = manifest_len};
        uri = integrated_uri;
    }

    /* "TEEP-Device" */
    uint8_t component_id_0[] = {0x54, 0x45, 0x45, 0x50, 0x2D, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65};
    /* "SecureFS" */
    uint8_t component_id_1[] = {0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x46, 0x53};
    /* "config.json" */
    uint8_t component_id_2[] = {0x63, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x2E, 0x6A, 0x73, 0x6F, 0x6E};

    suit_common_t *common = &manifest->common;
    /* suit-dependencies */
    common->dependencies.len = 1;
    suit_digest_t *depending_digest = &common->dependencies.dependency[0].digest;
    *depending_digest = *digest;

    /* suit-components */
    common->components.len = 1;
    common->components.comp_id[0].len = 3;
    common->components.comp_id[0].identifier[0] = (suit_buf_t){.ptr = component_id_0, .len = sizeof(component_id_0)};
    common->components.comp_id[0].identifier[1] = (suit_buf_t){.ptr = component_id_1, .len = sizeof(component_id_1)};
    common->components.comp_id[0].identifier[2] = (suit_buf_t){.ptr = component_id_2, .len = sizeof(component_id_2)};

    /* suit-common-sequence */
    uint8_t vendor_id[] = {0xC0, 0xDD, 0xD5, 0xF1, 0x52, 0x43, 0x56, 0x60, 0x87, 0xDB, 0x4F, 0x5B, 0x0A, 0xA2, 0x6C, 0x2F};
    uint8_t class_id[] = {0xDB, 0x42, 0xF7, 0x09, 0x3D, 0x8C, 0x55, 0xBA, 0xA8, 0xC5, 0x26, 0x5F, 0xC5, 0x82, 0x0F, 0x4E};
    suit_command_sequence_t *cmd_seq = &common->cmd_seq;
    cmd_seq->len = 4;

    suit_parameters_list_t *params_list;
    cmd_seq->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    cmd_seq->commands[0].value.uint64 = 0;
    cmd_seq->commands[1].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &cmd_seq->commands[1].value.params_list;
    params_list->len = 4;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    uint8_t image_digest_sha256[] = {0xAA, 0xAB, 0xCC, 0xCD, 0xEE, 0xEF, 0x00, 0x01, 0x22, 0x23, 0x44, 0x45, 0x66, 0x67, 0x88, 0x89, 0xAB, 0xBB, 0xCD, 0xDD, 0xEF, 0xFF, 0x01, 0x11, 0x23, 0x33, 0x45, 0x55, 0x67, 0x77, 0x89, 0x99};
    suit_digest_t image_digest;
    image_digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    image_digest.bytes.ptr = image_digest_sha256;
    image_digest.bytes.len = sizeof(image_digest_sha256);
    params_list->params[2].label = SUIT_PARAMETER_IMAGE_DIGEST,
    params_list->params[2].value.digest = image_digest;;

    params_list->params[3].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[3].value.uint64 = 64;

    cmd_seq->commands[2].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15; // report all

    cmd_seq->commands[3].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[3].value.uint64 = 15; // report all

    /* process-dependency */
    manifest->sev_man_mem.dependency_resolution_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *dependency_resolution = &manifest->sev_man_mem.dependency_resolution;
    dependency_resolution->len = 4;
    dependency_resolution->commands[0].label = SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX;
    dependency_resolution->commands[0].value.uint64 = 0;

    dependency_resolution->commands[1].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &dependency_resolution->commands[1].value.params_list;
    params_list->len = 1;
    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = (const void *)uri;
    params_list->params[0].value.string.len = strlen(uri);

    dependency_resolution->commands[2].label = SUIT_DIRECTIVE_FETCH;
    dependency_resolution->commands[2].value.uint64 = 2;
    dependency_resolution->commands[3].label = SUIT_CONDITION_IMAGE_MATCH;
    dependency_resolution->commands[3].value.uint64 = 15;

    /* install */
    const char data_uri[] = "https://example.org/config.json";
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 6;
    install->commands[0].label = SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX;
    install->commands[0].value.uint64 = 0;
    install->commands[1].label = SUIT_DIRECTIVE_PROCESS_DEPENDENCY;
    install->commands[1].value.uint64 = 0;

    install->commands[2].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    install->commands[2].value.uint64 = 0;
    install->commands[3].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    params_list = &install->commands[3].value.params_list;
    params_list->len = 1;
    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = (const void *)data_uri;
    params_list->params[0].value.string.len = strlen(data_uri);

    install->commands[4].label = SUIT_DIRECTIVE_FETCH;
    install->commands[4].value.uint64 = 2;
    install->commands[5].label = SUIT_CONDITION_IMAGE_MATCH;
    install->commands[5].value.uint64 = 15;

    /* validate */
    suit_command_sequence_t *validate = &manifest->unsev_mem.validate;
    validate->len = 2;
    validate->commands[0].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
    validate->commands[0].value.uint64 = 0;
    validate->commands[1].label = SUIT_CONDITION_IMAGE_MATCH;
    validate->commands[1].value.uint64 = 15;


    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    mode = SUIT_DECODE_MODE_STRICT;
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

    if (output_manifest_file != NULL) {
        size_t w_len = write_to_file(output_manifest_file, encode_len, encode_buf);
        if (w_len != encode_len) {
            printf("main : Fail to write to %s\n", output_manifest_file);
        }
    }
    else {
        printf("main : Skip to write to a file (dry-run).\n");
    }

    return EXIT_SUCCESS;
}
