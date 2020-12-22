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

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 3) {
        printf("suit_manifest_parser <manifest file path> <public key path>");
        return EXIT_FAILURE;
    }

    // Read der file.
    printf("\nmain : Read DER file.\n");
    uint8_t der_buf[PRIME256V1_PUBLIC_KEY_DER_SIZE];
    size_t der_len = read_from_file(argv[2], PRIME256V1_PUBLIC_KEY_DER_SIZE, der_buf);
    if (!der_len) {
        printf("main : Can't read DER file.\n");
        return EXIT_FAILURE;
    }
    suit_print_hex(der_buf, der_len);
    printf("\n");

    // Read key from der file.
    // This code is only available for openssl prime256v1.
    printf("\nmain : Read public key from DER file.\n");
    char key_buf[PRIME256V1_PUBLIC_KEY_CHAR_SIZE];
    read_prime256v1_public_key(der_buf, key_buf);
    printf("%s\n", key_buf);

    // Read manifest file.
    printf("\nmain : Read Manifest file.\n");
    uint8_t manifest_buf[MAX_FILE_BUFFER_SIZE];
    size_t manifest_len = read_file(argv[1], MAX_FILE_BUFFER_SIZE, manifest_buf);
    if (!manifest_len) {
        printf("main : Can't read Manifest file.\n");
        return EXIT_FAILURE;
    }
    suit_print_hex(manifest_buf, manifest_len);
    printf("\n");

    // Decode manifest file.
    printf("\nmain : Decode Manifest file.\n");
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
#ifdef SKIP_ERROR
    mode = SUIT_DECODE_MODE_SKIP_ANY_ERROR;
#endif
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_buf_t buf = {.ptr = manifest_buf, .len = manifest_len};
    int32_t result = suit_set_envelope(mode, &buf, &envelope, key_buf);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't parse Manifest file.\n");
        return EXIT_FAILURE;
    }

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    result = suit_print_envelope(mode, &envelope, 2);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't print Manifest file.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
