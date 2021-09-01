/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "qcbor/qcbor.h"
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_manifest_process.h"
#include "suit_cose.h"
#include "suit_examples_common.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"

#define MAX_FILE_BUFFER_SIZE            2048

#define NUM_PUBLIC_KEYS                 2
/* TC signer's public_key */
const uint8_t der_public_keys[NUM_PUBLIC_KEYS][PRIME256V1_PUBLIC_KEY_DER_SIZE] = {
    { /* TC signer's public key */
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x84, 0x96, 0x81,
        0x1a, 0xae, 0x0b, 0xaa, 0xab, 0xd2, 0x61, 0x57, 0x18, 0x9e,
        0xec, 0xda, 0x26, 0xbe, 0xaa, 0x8b, 0xf1, 0x1b, 0x6f, 0x3f,
        0xe6, 0xe2, 0xb5, 0x65, 0x9c, 0x85, 0xdb, 0xc0, 0xad, 0x3b,
        0x1f, 0x2a, 0x4b, 0x6c, 0x09, 0x81, 0x31, 0xc0, 0xa3, 0x6d,
        0xac, 0xd1, 0xd7, 0x8b, 0xd3, 0x81, 0xdc, 0xdf, 0xb0, 0x9c,
        0x05, 0x2d, 0xb3, 0x39, 0x91, 0xdb, 0x73, 0x38, 0xb4, 0xa8,
        0x96
    },/* TAM's public key */
    {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x4d, 0x5e, 0x5f,
        0x33, 0x67, 0xec, 0x6e, 0x41, 0x1f, 0x0e, 0xc3, 0x97, 0x45,
        0x2a, 0xc0, 0x2e, 0x65, 0x41, 0xb2, 0x12, 0x76, 0x13, 0x14,
        0x54, 0x8a, 0x62, 0x93, 0x79, 0x26, 0x4c, 0x5a, 0x44, 0x30,
        0x8a, 0xef, 0xfc, 0x28, 0x5e, 0x45, 0x2e, 0xde, 0x34, 0x3c,
        0x0f, 0x35, 0xd2, 0x1e, 0x0e, 0x2d, 0x37, 0x51, 0xf8, 0xbd,
        0x32, 0x49, 0x6f, 0x90, 0xaf, 0x26, 0x4d, 0x68, 0x6e, 0xcd,
        0xed
    }
};

size_t read_file(const char *file_path, const size_t write_buf_len, uint8_t *write_buf) {
    size_t read_len = 0;
    FILE* fp = fopen(file_path, "rb");
    if (fp == NULL) {
        return 0;
    }
    read_len = fread(write_buf, 1, write_buf_len, fp);
    fclose(fp);
    return read_len;
}

suit_err_t print_install(suit_install_args_t *install_args)
{
    printf("suit-install : {\n");
    int print_len = 16;
    if (0 <= install_args && install_args->uri.len < print_len) {
        print_len = (int)install_args->uri.len;
    }
    printf("  uri: %.*s", print_len, (char *)install_args->uri.ptr);
    printf("}\n");
    return SUIT_SUCCESS;
}

suit_err_t print_validate(suit_validate_args_t *validate_args)
{
    printf("suit-validate : {\n");
    suit_digest_t *digest = &validate_args->image_digest;
    printf("  suit-digest: {alg: %d, digest: ", digest->algorithm_id);
    suit_print_hex_in_max(digest->bytes.ptr, digest->bytes.len, digest->bytes.len);
    printf("}\n");
    return SUIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 2) {
        printf("suit_manifest_process <manifest file path> ...");
        return EXIT_FAILURE;
    }
    int32_t result = 0;
    int i;
    char char_public_keys[NUM_PUBLIC_KEYS][PRIME256V1_PUBLIC_KEY_CHAR_SIZE + 1];

    suit_inputs_t suit_inputs = {0};
    suit_callbacks_t suit_callbacks = {0};
    suit_callbacks.suit_install = print_install;
    suit_callbacks.suit_validate = print_validate;
    suit_inputs.manifest_len = 0;
    suit_inputs.key_len = NUM_PUBLIC_KEYS;

    // Read key from der file.
    // This code is only available for openssl prime256v1.
    printf("\nmain : Read public key from DER file.\n");
    for (i = 0; i < NUM_PUBLIC_KEYS; i++) {
        read_prime256v1_public_key(der_public_keys[i], char_public_keys[i]);
        printf("%s\n", char_public_keys[i]);
        result = suit_create_es256_public_key(char_public_keys[i], &suit_inputs.public_keys[i]);
    }
    // Read manifest file.
    printf("\nmain : Read Manifest file.\n");
    uint8_t manifests_buf[SUIT_MAX_ARRAY_LENGTH][MAX_FILE_BUFFER_SIZE];
    for (i = 1; i < argc; i++) {
        UsefulBufC *manifest = &suit_inputs.manifests[i - 1];
        size_t manifest_len = read_file(argv[i], MAX_FILE_BUFFER_SIZE, manifests_buf[i - 1]);
        if (!manifest_len) {
            printf("main : Can't read Manifest file.\n");
            goto out;
        }
        manifest->ptr = manifests_buf[i - 1];
        manifest->len = manifest_len;
        suit_inputs.manifest_len++;
    }

    // Decode manifest file.
    printf("\nmain : Decode Manifest file.\n");
    result = suit_process_envelopes(&suit_inputs, &suit_callbacks);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't parse Manifest file. err=%d\n", result);
        return EXIT_FAILURE;
    }

out:
    return EXIT_SUCCESS;
}
