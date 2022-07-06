/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "qcbor/qcbor.h"
#include "csuit/suit_common.h"
#include "csuit/suit_manifest_data.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_cose.h"
#include "suit_examples_common.h"
#include "trust_anchor_prime256v1.h"
#include "trust_anchor_prime256v1_pub.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#define MAX_FILE_BUFFER_SIZE            2048

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 1) {
        printf("suit_manifest_parser <manifest file path>\n");
        return EXIT_FAILURE;
    }
    int32_t result = 0;
    char *manifest_file = argv[1];
    const unsigned char *public_key = trust_anchor_prime256v1_public_key;
    const unsigned char *private_key = trust_anchor_prime256v1_private_key;
    struct t_cose_key cose_key;

    result = suit_create_es256_key_pair(private_key, public_key, &cose_key);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to create putlic key. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Read manifest file.
    printf("main : Read Manifest file.\n");
    uint8_t manifest_buf[MAX_FILE_BUFFER_SIZE];
    size_t manifest_len = read_from_file(manifest_file, MAX_FILE_BUFFER_SIZE, manifest_buf);
    if (!manifest_len) {
        printf("main : Can't read Manifest file.\n");
        return EXIT_FAILURE;
    }
    suit_print_hex(manifest_buf, manifest_len);
    printf("\n\n");

    // Decode manifest file.
    printf("main : Decode Manifest file.\n");
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
#ifdef SKIP_ERROR
    mode = SUIT_DECODE_MODE_SKIP_ANY_ERROR;
#endif
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_buf_t buf = {.ptr = manifest_buf, .len = manifest_len};
    result = suit_decode_envelope(mode, &buf, &envelope, &cose_key);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't parse Manifest file. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    result = suit_print_envelope(mode, &envelope, 2);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't print Manifest file. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Encode manifest.
    uint8_t encode_buf[MAX_FILE_BUFFER_SIZE];
    size_t encode_len = MAX_FILE_BUFFER_SIZE;
    printf("\nmain : Encode Manifest.\n");
    result = suit_encode_envelope(mode, &envelope, &cose_key, encode_buf, &encode_len);
    if (result != SUIT_SUCCESS) {
        printf("main : Fail to encode. %d\n", result);
        return EXIT_FAILURE;
    }

    // Compare whole and 
    if (manifest_len != encode_len) {
        printf("main : Lengthes differ %ld => %ld\n", manifest_len, encode_len);
        suit_print_hex_in_max(manifest_buf, manifest_len, manifest_len);
        printf("\n");
        suit_print_hex_in_max(encode_buf, encode_len, encode_len);
        printf("\n\n");
        return EXIT_FAILURE;
    }
    else if (memcmp(manifest_buf, encode_buf, manifest_len) != 0) {
        if (memcmp(&manifest_buf[0], &encode_buf[0], 57) != 0 ||
            memcmp(&manifest_buf[57 + 64], &encode_buf[57 + 64], manifest_len - (57 + 64))) {
            printf("main : encoded binary is differ from original\n");
            suit_print_hex_in_max(manifest_buf, manifest_len, manifest_len);
            printf("\n");
            suit_print_hex_in_max(encode_buf, encode_len, encode_len);
            printf("\n\n");
            return EXIT_FAILURE;
        }
        else {
            printf("main : Whole binaries but COSE_Sign1 signature match.\n\n");
        }
    }
    else {
        printf("main : Whole binaries match.\n\n");
    }

out:
    suit_free_key(&cose_key);
    return EXIT_SUCCESS;
}
