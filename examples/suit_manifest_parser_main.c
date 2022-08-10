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
#include "tam_es256_private_key.h"
#include "tam_es256_public_key.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#define MAX_FILE_BUFFER_SIZE            4096

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 1) {
        printf("%s <manifest file path> [tabstop 4]\n", argv[0]);
        return EXIT_FAILURE;
    }
    uint16_t tabstop = 4;
    if (argc >= 3) {
        tabstop = atoi(argv[2]);
    }
    suit_err_t result = 0;
    char *manifest_file = argv[1];
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];

    result = suit_key_init_es256_key_pair(trust_anchor_prime256v1_private_key, trust_anchor_prime256v1_public_key, &mechanisms[0].key);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to create putlic key. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanisms[0].cose_tag = CBOR_TAG_COSE_SIGN1;
    mechanisms[0].use = false;

    result = suit_key_init_es256_key_pair(tam_es256_private_key, tam_es256_public_key, &mechanisms[1].key);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to create putlic key. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanisms[1].cose_tag = CBOR_TAG_COSE_SIGN1;
    mechanisms[1].use = false;

    // Read manifest file.
    printf("main : Read Manifest file.\n");
    uint8_t manifest_buf[MAX_FILE_BUFFER_SIZE];
    size_t manifest_len = read_from_file(manifest_file, MAX_FILE_BUFFER_SIZE, manifest_buf);
    if (!manifest_len) {
        printf("main : Failed to read Manifest file.\n");
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
    result = suit_decode_envelope(mode, &buf, &envelope, mechanisms);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to parse Manifest file. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    result = suit_print_envelope(mode, &envelope, 4, tabstop);
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
    printf("main : Total buffer memory usage was %ld/%ld bytes\n", ret_pos + encode_len - encode_buf, sizeof(encode_buf));

    if (manifest_len != encode_len) {
        printf("main : The manifest length is changed %ld => %ld\n", manifest_len, encode_len);
        printf("#### ORIGINAL ####\n");
        suit_print_hex_in_max(manifest_buf, manifest_len, manifest_len);
        printf("\n#### ENCODED ####\n");
        suit_print_hex_in_max(ret_pos, encode_len, encode_len);
        printf("\n\n");
        return EXIT_FAILURE;
    }
    else if (memcmp(manifest_buf, ret_pos, manifest_len) != 0) {
        if (memcmp(&manifest_buf[0], &ret_pos[0], 57) != 0 ||
            memcmp(&manifest_buf[57 + 64], &ret_pos[57 + 64], manifest_len - (57 + 64))) {
            printf("main : encoded binary is differ from original\n");
            printf("#### ORIGINAL ####\n");
            suit_print_hex_in_max(manifest_buf, manifest_len, manifest_len);
            printf("\n#### ENCODED ####\n");
            suit_print_hex_in_max(ret_pos, encode_len, encode_len);
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

    suit_free_key(&mechanisms[0].key);
    suit_free_key(&mechanisms[1].key);
    return EXIT_SUCCESS;
}
