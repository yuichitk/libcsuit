/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "suit_common.h"

void suit_print_hex_in_max(const uint8_t *array, const int32_t size, const int32_t max_print_size) {
    if (size <= max_print_size) {
        suit_print_hex(array, size);
    }
    else {
        suit_print_hex(array, max_print_size);
        printf("..");
    }
}

void suit_print_hex(const uint8_t *array, int32_t size) {
    for (int32_t i = 0; i < size; i++) {
        if (array[i] == 0) {
            printf("0x00 ");
            continue;
        }
        printf("%#04x ", (unsigned char)array[i]);
    }
}

void suit_debug_print(QCBORDecodeContext *message,
                      QCBORItem *item,
                      QCBORError *error,
                      const char *func_name,
                      uint8_t expecting) {
    size_t cursor = UsefulInputBuf_Tell(&message->InBuf);
    size_t len = UsefulInputBuf_GetBufferLength(&message->InBuf) - cursor;
    uint8_t *at = (uint8_t *)message->InBuf.UB.ptr + cursor;

    len = (len > 12) ? 12 : len;

    printf("DEBUG: %s\n", func_name);
    printf("msg[%ld:%ld] = ", cursor, cursor + len);
    suit_print_hex(at, len);
    printf("\n");

    if (*error != 0) {
        printf("    Error! nCBORError = %d\n", *error);
    }
    if (expecting != QCBOR_TYPE_ANY && expecting != item->uDataType) {
        printf("    item->uDataType %d != %d\n", item->uDataType, expecting);
    }
}
