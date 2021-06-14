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

/*!
    \file   suit_common.h
    \brief  Declarations of common parameters and functions.
 */

/*!
    \brief  libcsuit SUCCESS/ERROR result
 */
typedef enum {
    SUIT_SUCCESS                        = 0, /*! success */
    SUIT_ERR_FATAL                      = 1, /*! unknown error, e.g. occurred out of SUIT */
    SUIT_ERR_NO_MEMORY                  = 2, /*! exceed the allocated memory */
    SUIT_ERR_INVALID_TYPE_OF_ARGUMENT   = 3, /*! type of an item is not expected */
    SUIT_ERR_NO_MORE_ITEMS              = 4, /*! mandatory items in array is not appeared */
    SUIT_ERR_NOT_IMPLEMENTED            = 5, /*! parser is not implemented */
    SUIT_ERR_FAILED_TO_VERIFY           = 6, /*! COSE or hash digest verification failure */
    SUIT_ERR_AUTHENTICATION_POSITION    = 7, /*! suit-authentication-block MUST come before any element, except suit-delegation */
} suit_err_t;

/*! \brief abort immediately on any error */
#define SUIT_DECODE_MODE_STRICT                 0
/*! \brief through but report on verification failure */
#define SUIT_DECODE_MODE_SKIP_SIGN_FAILURE      1
/*! \brief through unknown or unimplemented element(key or value) */
#define SUIT_DECODE_MODE_SKIP_UNKNOWN_ELEMENT   2
/*! \brief preserve successfully parsed elements on error in Map/Array */
#define SUIT_DECODE_MODE_PRESERVE_ON_ERROR      4
/*! \brief through excepting fatal error */
#define SUIT_DECODE_MODE_SKIP_ANY_ERROR       255

suit_err_t suit_error_from_qcbor_error(QCBORError error);
suit_err_t suit_print_hex_in_max(const uint8_t *array, const size_t size, const size_t max_print_size);
suit_err_t suit_print_hex(const uint8_t *array, size_t size);
suit_err_t suit_print_bytestr(const uint8_t *bytes, size_t len);
void suit_debug_print(QCBORDecodeContext *message, QCBORItem *item, const char *func_name, uint8_t expecting);
bool suit_qcbor_value_is_uint64(QCBORItem *item);
bool suit_qcbor_value_is_uint32(QCBORItem *item);
suit_err_t suit_qcbor_get_next_uint(QCBORDecodeContext *message, QCBORItem *item);
suit_err_t suit_qcbor_get_next(QCBORDecodeContext *message, QCBORItem *item, uint8_t data_type);
suit_err_t suit_qcbor_get(QCBORDecodeContext *message, QCBORItem *item, bool next, uint8_t data_type);
suit_err_t suit_qcbor_peek_next(QCBORDecodeContext *message, QCBORItem *item, uint8_t data_type);
bool suit_qcbor_skip_any(QCBORDecodeContext *message, QCBORItem *item);
size_t suit_qcbor_calc_rollback(QCBORItem *item);
bool suit_continue(uint8_t mode, suit_err_t result);
#endif  // SUIT_COMMON_H
