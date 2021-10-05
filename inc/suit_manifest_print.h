/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_PRINT_H
#define SUIT_MANIFEST_PRINT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "suit_manifest_data.h"

#define SUIT_MAX_PRINT_BYTE_COUNT        5
#define SUIT_MAX_PRINT_TEXT_COUNT        64

extern const char* SUIT_ENVELOPE_KEY_NUM_TO_STRING[];
extern const char* SUIT_MANIFEST_KEY_NUM_TO_STRING[];
extern const char* SUIT_COMMAND_SEQUENCE_NUM_TO_STRING[];
extern const char* SUIT_PARAMETER_NUM_TO_STRING[];

const char* suit_err_to_str(suit_err_t error);
suit_err_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list, const uint32_t indent_space);
suit_err_t suit_print_cmd_seq(uint8_t mode, const suit_command_sequence_t *cmd_seq, const uint32_t indent_space);
suit_err_t suit_print_component_identifier(const suit_component_identifier_t *identifier);
suit_err_t suit_print_digest(const suit_digest_t *digest, const uint32_t indent_space);
suit_err_t suit_print_envelope(uint8_t mode, const suit_envelope_t *envelope, const uint32_t indent_space);
#endif  /* SUIT_MANIFEST_PRINT_H */
