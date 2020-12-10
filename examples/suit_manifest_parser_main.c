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
    if (argc < 2) {
        printf("suit_manifest_parser <manifest file path>");
        return EXIT_FAILURE;
    }

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
    QCBORDecodeContext decode_context;
    QCBORDecode_Init(&decode_context,
                     (UsefulBufC){manifest_buf, manifest_len},
                     QCBOR_DECODE_MODE_NORMAL);
    QCBORItem  item;
    QCBORError error;

    suit_envelope_t envelope = (suit_envelope_t){ 0 };
    int32_t result = suit_set_envelope(&decode_context, &item, &error, &envelope);
    if (result) {
        printf("main : Can't parse Manifest file.\n");
        return EXIT_FAILURE;
    }
    QCBORDecode_Finish(&decode_context);

    // Print manifest.
    printf("\nmain : Print Manifest.\n");
    suit_print_envelope(&envelope);

    return EXIT_SUCCESS;
}
