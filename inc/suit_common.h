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
#include "qcbor/qcbor.h"


#define SUIT_FAILED_TO_VERIFY               6 // COSE verification failure or hash digest failure
#define SUIT_NOT_IMPLEMENTED                5 // parser is not implemented
#define SUIT_NO_MORE_ITEMS                  4 // mandatory items in array is not appeared
#define SUIT_INVALID_TYPE_OF_ARGUMENT       3 // type of an item is not expected
#define SUIT_NO_MEMORY                      2 // items exceed the allocated memory
#define SUIT_FATAL_ERROR                    1 // unknown error
#define SUIT_SUCCESS                        0

#define SUIT_DECODE_MODE_STRICT                 0b00000000 // abort immediately on any error
#define SUIT_DECODE_MODE_SKIP_SIGN_FAILURE      0b00000001 // through but report on verification failure
#define SUIT_DECODE_MODE_SKIP_UNKNOWN_ELEMENT   0b00000010 // through unknown or unimplemented element(key or value)
#define SUIT_DECODE_MODE_PRESERVE_ON_ERROR      0b00000100 // preserve successfully parsed elements on error in Map/Array
#define SUIT_DECODE_MODE_SKIP_ANY_ERROR         0b11111111 // through excepting fatal error

int32_t suit_error_from_qcbor_error(QCBORError error);
int32_t suit_print_hex_in_max(const uint8_t *array, const size_t size, const size_t max_print_size);
int32_t suit_print_hex(const uint8_t *array, size_t size);
void suit_debug_print(QCBORDecodeContext *message, QCBORItem *item, const char *func_name, uint8_t expecting);
bool suit_continue(uint8_t mode, int32_t result);
#endif  // SUIT_COMMON_H
