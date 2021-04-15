/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "qcbor/qcbor.h"
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_manifest_print.h"
#include "suit_cose.h"
#include "suit_examples_common.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"

#define MAX_FILE_BUFFER_SIZE            2048

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 2) {
        printf("suit_manifest_encode <private key path> <output manifest file path>");
        return EXIT_FAILURE;
    }
    char *private_key_file = argv[1];
    char *manifest_file = argv[2];
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
    manifest->sequence_number = 2;

    uint8_t component_id[] = {0x00};
    suit_common_t *common = &manifest->common;
    common->components.len = 1;
    common->components.comp_id[0].len = 1;
    common->components.comp_id[0].identifier[0] = (suit_buf_t){.ptr = component_id, .len = sizeof(component_id)};

    uint8_t vendor_id[] = {0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE};
    uint8_t class_id[] = {0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48, 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45};
    suit_command_sequence_t *cmd_seq = &common->cmd_seq;
    cmd_seq->len = 3;

    suit_parameters_list_t *params_list;
    cmd_seq->commands[0].label = SUIT_DIRECTIVE_SET_PARAMETERS;
    params_list = &cmd_seq->commands[0].value.params_list;
    params_list->len = 4;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    uint8_t image_digest[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    params_list->params[2].label = SUIT_PARAMETER_IMAGE_DIGEST,
    params_list->params[2].value.digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    params_list->params[2].value.digest.bytes.ptr = image_digest;
    params_list->params[2].value.digest.bytes.len = sizeof(image_digest);

    params_list->params[3].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[3].value.uint64 = 34768;

    cmd_seq->commands[1].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[1].value.uint64 = 15; // report all

    cmd_seq->commands[2].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15; // report all

    /* install */
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 1;
    install->commands[0].label = SUIT_DIRECTIVE_SET_PARAMETERS;

    params_list = &install->commands[0].value.params_list;
    params_list->len = 1;

    uint8_t uri[] = "http://localhost:8888/TAs/8d82573a-926d-4754-9353-32dc29997f74.ta";
    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = uri;
    params_list->params[0].value.string.len = sizeof(uri) - 1;


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
    result = suit_encode_envelope(&envelope, &key_pair, encode_buf, &encode_len);
    if (result != SUIT_SUCCESS) {
        printf("main : Fail to encode. %d\n", result);
        return EXIT_FAILURE;
    }

    size_t w_len = write_to_file(manifest_file, encode_len, encode_buf);
    if (w_len != encode_len) {
        printf("main : Fail to write to %s\n", manifest_file);
    }

    return EXIT_SUCCESS;
}
