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
        printf("suit_manifest_parser <manifest file path> <public key path> [<private key path>]");
        return EXIT_FAILURE;
    }
    int32_t result = 0;
    char *manifest_file = argv[1];
    char *public_key_file = argv[2];
    char *private_key_file = (argc == 3) ? NULL : argv[3];
    char public_key[PRIME256V1_PUBLIC_KEY_CHAR_SIZE + 1];
    char private_key[PRIME256V1_PRIVATE_KEY_CHAR_SIZE + 1];
    t_cose_key cose_key;

    // Read der file.
    if (private_key_file != NULL) {
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
        result = suit_create_es256_key_pair(private_key, public_key, &cose_key);
    }
    else {
        printf("\nmain : Read DER file.\n");
        uint8_t der_buf[PRIME256V1_PUBLIC_KEY_DER_SIZE];
        size_t der_len = read_from_file(public_key_file, PRIME256V1_PUBLIC_KEY_DER_SIZE, der_buf);
        if (!der_len) {
            printf("main : Can't read DER file.\n");
            return EXIT_FAILURE;
        }
        suit_print_hex(der_buf, der_len);
        printf("\n");

        // Read key from der file.
        // This code is only available for openssl prime256v1.
        printf("\nmain : Read public key from DER file.\n");
        read_prime256v1_public_key(der_buf, public_key);
        printf("%s\n", public_key);
        result = suit_create_es256_public_key(public_key, &cose_key);
    }

    // Read manifest file.
    printf("\nmain : Read Manifest file.\n");
    uint8_t manifest_buf[MAX_FILE_BUFFER_SIZE];
    size_t manifest_len = read_file(manifest_file, MAX_FILE_BUFFER_SIZE, manifest_buf);
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
    result = suit_decode_envelope(mode, &buf, &envelope, &cose_key);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't parse Manifest file. err=%d\n", result);
        return EXIT_FAILURE;
    }

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    result = suit_print_envelope(mode, &envelope, 2);
    if (result != SUIT_SUCCESS) {
        printf("main : Can't print Manifest file. err=%d\n", result);
        return EXIT_FAILURE;
    }

    // Encode manifest.
    uint8_t encode_buf[MAX_FILE_BUFFER_SIZE];
    size_t encode_len = MAX_FILE_BUFFER_SIZE;
    printf("\nmain : Encode Manifest.\n");
    result = suit_encode_envelope(mode, &envelope, &cose_key, encode_buf, &encode_len);
    EC_KEY_free(cose_key.k.key_ptr);
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

    return EXIT_SUCCESS;
}
