/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "suit_common.h"

int32_t suit_error_from_qcbor_error(QCBORError error) {
    switch (error) {
        case QCBOR_SUCCESS:
            return SUIT_SUCCESS;
        case QCBOR_ERR_BUFFER_TOO_SMALL:
            return SUIT_NO_MEMORY;
        default:
            return SUIT_FATAL_ERROR;
    }
}

int32_t suit_print_hex_in_max(const uint8_t *array, const size_t size, const size_t max_print_size) {
    int32_t result = SUIT_SUCCESS;
    if (size <= max_print_size) {
        result = suit_print_hex(array, size);
    }
    else {
        result = suit_print_hex(array, max_print_size);
        printf("..");
    }
    return result;
}

int32_t suit_print_hex(const uint8_t *array, size_t size) {
    if (array == NULL) {
        return SUIT_FATAL_ERROR;
    }
    for (size_t i = 0; i < size; i++) {
        printf("0x%02x ", (unsigned char)array[i]);
    }
    return SUIT_SUCCESS;
}

int32_t suit_print_bytestr(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL)
        return( SUIT_FATAL_ERROR );

    for(unsigned int idx=0; idx < len; idx++)
    {
        printf("%02X", bytes[idx]);
    }
    return( SUIT_FATAL_ERROR );
}

void suit_debug_print(QCBORDecodeContext *message,
                      QCBORItem *item,
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

    if (expecting != QCBOR_TYPE_ANY && expecting != item->uDataType) {
        printf("    item->uDataType %d != %d\n", item->uDataType, expecting);
    }
}

bool suit_continue(uint8_t mode, int32_t result) {
    bool ret = false;
    switch (result) {
        case SUIT_SUCCESS:
            ret = true;
            break;
        case SUIT_FAILED_TO_VERIFY:
            if (mode & SUIT_DECODE_MODE_SKIP_SIGN_FAILURE) {
                ret = true;
            }
            break;
        case SUIT_NOT_IMPLEMENTED:
        case SUIT_INVALID_TYPE_OF_ARGUMENT:
            if (mode & SUIT_DECODE_MODE_SKIP_UNKNOWN_ELEMENT) {
                ret = true;
            }
        case SUIT_NO_MEMORY:
        case SUIT_FATAL_ERROR:
        default:
            break;
    }
    if (ret == false) {
        return false;
    }
    return true;
}
