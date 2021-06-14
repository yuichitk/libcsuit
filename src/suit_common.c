/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "suit_common.h"

suit_err_t suit_error_from_qcbor_error(QCBORError error) {
    switch (error) {
        case QCBOR_SUCCESS:
            return SUIT_SUCCESS;
        case QCBOR_ERR_BUFFER_TOO_SMALL:
            return SUIT_ERR_NO_MEMORY;
        case QCBOR_ERR_NO_MORE_ITEMS:
            return SUIT_ERR_NO_MORE_ITEMS;
        default:
            return SUIT_ERR_FATAL;
    }
}

suit_err_t suit_print_hex_in_max(const uint8_t *array, const size_t size, const size_t max_print_size) {
    suit_err_t result = SUIT_SUCCESS;
    if (size <= max_print_size) {
        result = suit_print_hex(array, size);
    }
    else {
        result = suit_print_hex(array, max_print_size);
        printf("..");
    }
    return result;
}

suit_err_t suit_print_hex(const uint8_t *array, size_t size) {
    if (array == NULL) {
        return SUIT_ERR_FATAL;
    }
    for (size_t i = 0; i < size; i++) {
        printf("0x%02x ", (unsigned char)array[i]);
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_bytestr(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL)
        return( SUIT_ERR_FATAL );

    for(unsigned int idx=0; idx < len; idx++)
    {
        printf("%02X", bytes[idx]);
    }
    return( SUIT_ERR_FATAL );
}

#ifdef DEBUG
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
#else
void suit_debug_print(QCBORDecodeContext *message,
                      QCBORItem *item,
                      const char *func_name,
                      uint8_t expecting) {}
#endif


bool suit_continue(uint8_t mode, suit_err_t result) {
    bool ret = false;
    switch (result) {
        case SUIT_SUCCESS:
            ret = true;
            break;
        case SUIT_ERR_FAILED_TO_VERIFY:
            if (mode & SUIT_DECODE_MODE_SKIP_SIGN_FAILURE) {
                ret = true;
            }
            break;
        case SUIT_ERR_NOT_IMPLEMENTED:
        case SUIT_ERR_INVALID_TYPE_OF_ARGUMENT:
            if (mode & SUIT_DECODE_MODE_SKIP_UNKNOWN_ELEMENT) {
                ret = true;
            }
        case SUIT_ERR_NO_MEMORY:
        case SUIT_ERR_FATAL:
        default:
            break;
    }
    if (ret == false) {
        return false;
    }
    return true;
}

suit_err_t suit_qcbor_get_next(QCBORDecodeContext *message, QCBORItem *item, uint8_t data_type) {
    QCBORError error;
    error = QCBORDecode_GetNext(message, item);
    switch (error) {
        case QCBOR_SUCCESS:
            break;
        case QCBOR_ERR_NO_MORE_ITEMS:
            return SUIT_ERR_NO_MORE_ITEMS;
        default:
            return SUIT_ERR_FATAL;
    }
    if (item->uDataType == QCBOR_TYPE_NONE) {
        return SUIT_ERR_NO_MORE_ITEMS;
    }
    else if (data_type != QCBOR_TYPE_ANY && item->uDataType != data_type) {
        return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_qcbor_peek_next(QCBORDecodeContext *message, QCBORItem *item, uint8_t data_type) {
    QCBORError error;
    error = QCBORDecode_PeekNext(message, item);
    switch (error) {
        case QCBOR_SUCCESS:
            break;
        case QCBOR_ERR_NO_MORE_ITEMS:
            return SUIT_ERR_NO_MORE_ITEMS;
        default:
            return SUIT_ERR_FATAL;
    }
    if (item->uDataType == QCBOR_TYPE_NONE) {
        return SUIT_ERR_NO_MORE_ITEMS;
    }
    else if (data_type != QCBOR_TYPE_ANY && item->uDataType != data_type) {
        return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_qcbor_get(QCBORDecodeContext *message, QCBORItem *item, bool next, uint8_t data_type) {
    if (next) {
        return suit_qcbor_get_next(message, item, data_type);
    }
    else if (data_type != QCBOR_TYPE_ANY && item->uDataType != data_type) {
        return SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
    }
    return SUIT_SUCCESS;
}

bool suit_qcbor_value_is_uint64(QCBORItem *item) {
    if (item->uDataType == QCBOR_TYPE_INT64) {
        if (item->val.int64 < 0) {
            return false;
        }
        /* there is no need to cast int64_t [0, INT32_MAX] value into uint64_t in the union */
    }
    else if (item->uDataType != QCBOR_TYPE_UINT64) {
        return false;
    }
    return true;
}

bool suit_qcbor_value_is_uint32(QCBORItem *item) {
    switch (item->uDataType) {
        case QCBOR_TYPE_INT64:
            if (item->val.int64 < 0 || item->val.int64 > UINT32_MAX) {
                return false;
            }
            break;
        case QCBOR_TYPE_UINT64:
            if (item->val.uint64 > UINT32_MAX) {
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

suit_err_t suit_qcbor_get_next_uint(QCBORDecodeContext *message, QCBORItem *item) {
    suit_err_t result = suit_qcbor_get_next(message, item, QCBOR_TYPE_ANY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    return (suit_qcbor_value_is_uint64(item)) ? SUIT_SUCCESS : SUIT_ERR_INVALID_TYPE_OF_ARGUMENT;
}

bool suit_qcbor_skip_any(QCBORDecodeContext *message, QCBORItem *item);

bool suit_qcbor_skip_array_and_map(QCBORDecodeContext *message, QCBORItem *item) {
    if (item->uDataType != QCBOR_TYPE_ARRAY && item->uDataType != QCBOR_TYPE_MAP) {
        return false;
    }
    size_t array_size = item->val.uCount;
    for (size_t i = 0; i < array_size; i++) {
        suit_err_t result = suit_qcbor_get_next(message, item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return false;
        }
        if (!suit_qcbor_skip_any(message, item)) {
            return false;
        }
    }
    return true;
}

bool suit_qcbor_skip_any(QCBORDecodeContext *message, QCBORItem *item) {
    switch (item->uDataType) {
        case QCBOR_TYPE_ARRAY:
        case QCBOR_TYPE_MAP:
            if (!suit_qcbor_skip_array_and_map(message, item)) {
                return false;
            }
            break;
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TEXT_STRING:
            break;
        default:
            return false;
    }
    return true;
}


/*!
    \brief  Calculate the length of the CBOR header.

    \param[in]  item    QCBOR item to be calculated.

    \return     This returns the length of the CBOR header.

    Counts the CBOR binary offset between the CBOR type and length declaration
    and current cursor = UsefulInputBuf_Tell(&context.InBuf)

    NOTE: If the item type is one of INT64, UINT64, TEXT_STRING, and BYTE_STRING,
    the current cursor is tail of the value,
    but with ARRAY, MAP, MAP_AS_ARRAY,
    the current cursor is tail of the type and length declaration.
 */
size_t suit_qcbor_calc_rollback(QCBORItem *item) {
    uint8_t type = item->uDataType;
    if (item->uDataType == QCBOR_TYPE_INT64 && suit_qcbor_value_is_uint64(item)) {
        type = QCBOR_TYPE_UINT64;
    }

    switch (type) {
        case QCBOR_TYPE_UINT64:
            if (item->val.uint64 <= 23) {
                return 1;
            }
            else if (item->val.uint64 <= UINT8_MAX) {
                return 2;
            }
            else if (item->val.uint64 <= UINT16_MAX) {
                return 3;
            }
            else if (item->val.uint64 <= UINT32_MAX) {
                return 5;
            }
            return 9;
        case QCBOR_TYPE_INT64:
            if (item->val.int64 + 1 + 23 >= 0) {
                return 1;
            }
            else if (item->val.int64 + 1 + UINT8_MAX >= 0) {
                return 2;
            }
            else if (item->val.int64 + 1 + UINT16_MAX >= 0) {
                return 3;
            }
            else if (item->val.int64 + 1 + UINT32_MAX >= 0) {
                return 5;
            }
            return 9;
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TEXT_STRING:
            if (item->val.string.len < 24) {
                return 1 + item->val.string.len;
            }
            else if (item->val.string.len <= UINT8_MAX) {
                return 2 + item->val.string.len;
            }
            else if (item->val.string.len <= UINT16_MAX) {
                return 3 + item->val.string.len;
            }
            else if (item->val.string.len <= UINT32_MAX) {
                return 5 + item->val.string.len;
            }
            return 9 + item->val.string.len;
        case QCBOR_TYPE_ARRAY:
        case QCBOR_TYPE_MAP:
            if (item->val.uCount < 24) {
                return 1;
            }
            else if (item->val.uCount < UINT8_MAX) {
                return 2;
            }
            else if (item->val.uCount < UINT16_MAX) {
                return 3;
            }
            else if (item->val.uCount < UINT32_MAX) {
                return 5;
            }
            return 9;
    }
    return 0;
}


