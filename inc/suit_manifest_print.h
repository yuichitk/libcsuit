/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_PRINT_H
#define SUIT_MANIFEST_PRINT_H

#include <stdio.h>
#include <string.h>
#include "suit_common.h"
#include "suit_manifest_data.h"

#define SUIT_MAX_PRINT_BYTE_COUNT        5
#define SUIT_MAX_PRINT_TEXT_COUNT        64

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
void suit_debug_print(QCBORDecodeContext *message, QCBORItem *item, const char *func_name, uint8_t expecting);

suit_err_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space);
suit_err_t suit_print_cmd_seq(uint8_t mode, const suit_command_sequence_t *cmd_seq, const uint32_t indent_space);
suit_err_t suit_print_component_identifier(const suit_component_identifier_t *identifier);
suit_err_t suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space);
suit_err_t suit_print_envelope(uint8_t mode, const suit_envelope_t *envelope, const uint32_t indent_space);
#endif  /* SUIT_MANIFEST_PRINT_H */
