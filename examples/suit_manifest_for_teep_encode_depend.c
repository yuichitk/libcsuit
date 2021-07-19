/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
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
    if (argc < 4) {
        printf("suit_for_teep_depending <manifest to depend> <uri> <private key path> <output manifest file path>");
        return EXIT_FAILURE;
    }
    char *input_manifest_file = argv[1];
    char *uri = argv[2];
    char *private_key_file = argv[3];
    char *output_manifest_file = argv[4];
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

    suit_digest_t *digest = &read_envelope.wrapper.digest[0];

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
    manifest->sequence_number = 2;

    uint8_t component_id[] = {0x00};
    suit_common_t *common = &manifest->common;
    /* suit-dependencies */
    common->dependencies.len = 1;
    suit_digest_t *depending_digest = &common->dependencies.dependency[0].digest;
    *depending_digest = *digest;
    /*
    depending_digest->algorithm_id = digest->algorithm_id;
    depending_digest->bytes.len = digest->bytes.len;
    depending_digest->bytes.ptr = digest->bytes.ptr;
    */

    /* suit-components */
    /*
    common->components.len = 1;
    common->components.comp_id[0].len = 1;
    common->components.comp_id[0].identifier[0] = (suit_buf_t){.ptr = component_id, .len = sizeof(component_id)};
    */

    suit_parameters_list_t *params_list;

    /*
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
    */

    /* process-dependency */
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 4;
    install->commands[0].label = SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX;
    install->commands[0].value.uint64 = 0;

    install->commands[1].label = SUIT_DIRECTIVE_SET_PARAMETERS;
    params_list = &install->commands[1].value.params_list;
    params_list->len = 1;

    /*
    uint8_t uri[] = "http://localhost:8888/TAs/8d82573a-926d-4754-9353-32dc29997f74.ta";
    */
    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = (uint8_t *)uri;
    params_list->params[0].value.string.len = strlen(uri);

    install->commands[2].label = SUIT_DIRECTIVE_FETCH;
    install->commands[2].value.uint64 = 15;

    install->commands[3].label = SUIT_DIRECTIVE_PROCESS_DEPENDENCY;
    install->commands[3].value.uint64 = 15; // report all


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

    size_t w_len = write_to_file(output_manifest_file, encode_len, encode_buf);
    if (w_len != encode_len) {
        printf("main : Fail to write to %s\n", output_manifest_file);
    }

    return EXIT_SUCCESS;
}
