/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "csuit/suit_common.h"
#include "csuit/suit_manifest_data.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_cose.h"
#include "suit_examples_common.h"
#include "trust_anchor_prime256v1.h"
#include "trust_anchor_prime256v1_pub.h"

#define MAX_FILE_BUFFER_SIZE            4096

int main(int argc, char *argv[]) {
    // check arguments.
    if (argc < 2) {
        fprintf(stderr, "%s <manifest file path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    suit_err_t result = 0;
    char *manifest_file = argv[1];
    suit_key_t cose_key;

    const unsigned char *public_key = trust_anchor_prime256v1_public_key;
    result = suit_key_init_es256_public_key(public_key, &cose_key);
    if (result != SUIT_SUCCESS) {
        fprintf(stderr, "main : Failed to create putlic key. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    // Read manifest file.
    uint8_t manifest_buf[MAX_FILE_BUFFER_SIZE];
    size_t manifest_len = read_from_file(manifest_file, MAX_FILE_BUFFER_SIZE, manifest_buf);
    if (!manifest_len) {
        fprintf(stderr, "main : Failed to read Manifest file.\n");
        return EXIT_FAILURE;
    }

    // Decode manifest file.
    uint8_t mode = SUIT_DECODE_MODE_STRICT;
#ifdef SKIP_ERROR
    mode = SUIT_DECODE_MODE_SKIP_ANY_ERROR;
#endif
    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    suit_buf_t buf = {.ptr = manifest_buf, .len = manifest_len};
    result = suit_decode_envelope(mode, &buf, &envelope, &cose_key);
    if (result != SUIT_SUCCESS) {
        fprintf(stderr, "main : Failed to parse Manifest file. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    suit_manifest_t *manifest = &envelope.manifest;
    fprintf(stdout, "[%ld,", manifest->sequence_number);
    for (size_t i = 0; i < manifest->common.components.len; i++) {
        suit_print_component_identifier(&manifest->common.components.comp_id[i]);
        fprintf(stdout, ",");
    }
    fprintf(stdout, "]");

    suit_free_key(&cose_key);
    return EXIT_SUCCESS;
}
