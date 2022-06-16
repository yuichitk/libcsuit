/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_PRINT_H
#define SUIT_MANIFEST_PRINT_H

/*!
    \file   suit_manifest_print.h
    \brief  Declarations of print functions and string values.
 */

#include <stdio.h>
#include <string.h>
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_manifest_process.h"

#define SUIT_MAX_PRINT_BYTE_COUNT        5
#define SUIT_MAX_PRINT_TEXT_COUNT        64
#define SUIT_MAX_PRINT_URI_COUNT         64

const char* suit_envelope_key_to_str(suit_envelope_key_t envelope_key);
const char* suit_manifest_key_to_str(suit_manifest_key_t manifest_key);
const char* suit_common_key_to_str(suit_common_key_t common_key);
const char* suit_command_sequence_key_to_str(suit_con_dir_key_t condition_directive);
const char* suit_parameter_key_to_str(suit_parameter_key_t parameter);
const char* suit_info_key_to_str(const suit_info_key_t info_key);
const char* suit_compression_algorithm_to_str(const suit_compression_algorithm_t algorithm);
const char* suit_unpack_algorithm_to_str(const suit_unpack_algorithm_t algorithm);
const char* suit_err_to_str(suit_err_t error);

suit_err_t suit_print_hex_in_max(const uint8_t *array, const size_t size, const size_t max_print_size);
suit_err_t suit_print_hex(const uint8_t *array, size_t size);
suit_err_t suit_print_bytestr(const uint8_t *bytes, size_t len);

suit_err_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space);
suit_err_t suit_print_cmd_seq(uint8_t mode, const suit_command_sequence_t *cmd_seq, const uint32_t indent_space);
suit_err_t suit_print_component_identifier(const suit_component_identifier_t *identifier);
suit_err_t suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space);
suit_err_t suit_print_envelope(uint8_t mode, const suit_envelope_t *envelope, const uint32_t indent_space);

/*!
    \brief  Print SUIT fetch callback

    \param[in]      fetch_args      Fetch and suit-report arguments. See \ref suit_fetch_args_t.
    \param[out]     fetch_ret       Fetch result. See \ref suit_fetch_ret_t.
    Triggered on \ref SUIT_DIRECTIVE_FETCH.
    \return         This returns one of the error codes defined by \ref suit_err_t.
*/
suit_err_t suit_fetch_callback(suit_fetch_args_t fetch_args, suit_fetch_ret_t *fetch_ret);

/*!
    \brief Print SUIT store callback
    \param[in]      store_args      Store and suit-report arguments. See \ref suit_store_args_t.
    Triggered on \ref SUIT_DIRECTIVE_FETCH of integrated-payload or integrated-dependency.
    \return         This returns one of the error codes defined by \ref suit_err_t.
*/
suit_err_t suit_store_callback(suit_store_args_t store_args);

/*!
    \brief Print SUIT copy callback
    \param[in]      copy_args       Copy and suit-report arguments. See \ref suit_copy_args_t.
    Triggered on \ref SUIT_DIRECTIVE_COPY.
    \return         This returns one of the error codes defined by \ref suit_err_t.
*/
suit_err_t suit_copy_callback(suit_copy_args_t copy_args);

/*!
    \brief Print SUIT run callback
    \param[in]      run_args        Run and suit-report arguments. See \ref suit_run_args_t.
    \return         This returns one of the error codes defined by \ref suit_err_t.
*/
suit_err_t suit_run_callback(suit_run_args_t run_args);

/*!
    \brief Print SUIT report callback
    \param[in]      report_args     Suit-report arguments and errors. See \ref suit_report_args_t.
    \return         This returns one of the error codes defined by \ref suit_err_t.
*/
suit_err_t suit_report_callback(suit_report_args_t report_args);

#endif  /* SUIT_MANIFEST_PRINT_H */
