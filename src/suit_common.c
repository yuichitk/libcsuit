/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "suit_common.h"

void print_hex_in_max(const uint8_t *array, const int32_t size, const int32_t max_print_size) {
    if (size <= max_print_size) {
        print_hex(array, size);
    }
    else {
        print_hex(array, max_print_size);
        printf("..");
    }
}

void print_hex(const uint8_t *array, int32_t size) {
    for (int32_t i = 0; i < size; i++) {
        if (array[i] == 0) {
            printf("0x00 ");
            continue;
        }
        printf("%#04x ", (unsigned char)array[i]);
    }
}
