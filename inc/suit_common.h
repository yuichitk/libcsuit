/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_COMMON_H
#define SUIT_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SUIT_UNEXPECTED_ERROR               2
#define SUIT_INVALID_TYPE_OF_ARGUMENT       1
#define SUIT_SUCCESS                        0

void print_hex_in_max(const uint8_t *array, const int32_t size, const int32_t max_print_size);
void print_hex(const uint8_t *array, int32_t size);

#endif  // SUIT_COMMON_H
