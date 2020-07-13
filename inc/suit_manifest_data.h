/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_DATA_H
#define SUIT_MANIFEST_DATA_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor.h"

#define SUIT_MAX_ARRAY_LENGTH           20

typedef enum suit_envelope_key {
    SUIT_INVALID_ENVELOPE_KEY           = 0,
    SUIT_DELEGATION                     = 1,
    SUIT_AUTHENTICATION                 = 2,
    SUIT_MANIFEST                       = 3,
    SUIT_MANIFEST_ENCRYPTION_INFO       = 4,
    SUIT_MANIFEST_ENCRYPTED             = 5
} suit_envelope_key_t;

typedef enum suit_manifest_key {
    SUIT_INVALID_MANIFEST_KEY           = 0,
    SUIT_MANIFEST_VERSION               = 1,
    SUIT_MANIFEST_SEQUENCE_NUMBER       = 2,
    SUIT_COMMON                         = 3,
    SUIT_REFERENCE_URI                  = 4,
    SUIT_DEPENDENCY_RESOLUTION          = 7,
    SUIT_PAYLOAD_FETCH                  = 8,
    SUIT_INSTALL                        = 9,
    SUIT_VALIDATE                       = 10,
    SUIT_LOAD                           = 11,
    SUIT_RUN                            = 12,
    SUIT_TEXT                           = 13,
    SUIT_COSWID                         = 14
} suit_manifest_key_t;

/*
 * bstr
 */
typedef struct suit_buf {
    size_t                          len;
    const uint8_t                   *ptr;
} suit_buf_t;

/*
 * SUIT_Digest
 */
typedef struct suit_digest {
    uint32_t                        algorithm_id;
    suit_buf_t                      bytes;
    // TODO :                       suit-digest-parameters
} suit_digest_t;

/*
 * SUIT_Component_Identifier
 */
typedef struct suit_component_identifier {
    size_t                          len;
    suit_buf_t                      identifer[SUIT_MAX_ARRAY_LENGTH];
} suit_component_identifier_t;

/*
 * SUIT_Components
 */
typedef struct suit_components {
    size_t                          len;
    suit_component_identifier_t     comp_id[SUIT_MAX_ARRAY_LENGTH];
} suit_components_t;

/*
 * SUIT_Parameters
 */
typedef struct suit_parameters {
    uint32_t                        label;
    union {
        suit_buf_t                  string;
        int64_t                     int64;
        uint64_t                    uint64;
        bool                        isNull;
    } value;
} suit_parameters_t;

/*
 * [+ SUIT_Parameters]
 */
typedef struct suit_parameters_list {
    size_t                          len;
    suit_parameters_t               params[SUIT_MAX_ARRAY_LENGTH];
} suit_parameters_list_t;

/*
 * (SUIT_Condition // SUIT_Directive // SUIT_Command_Custom)
 */
typedef struct suit_command_sequence_item {
    uint32_t                        label;
    union {
        suit_buf_t                  string;
        int64_t                     int64;
        uint64_t                    uint64;
        bool                        isNull;
        suit_parameters_list_t      params_list;
    } value;
} suit_command_sequence_item_t;

/*
 * SUIT_Command_Sequence
 */
typedef struct suit_command_sequence {
    size_t                          len;
    suit_command_sequence_item_t    commands[SUIT_MAX_ARRAY_LENGTH];
} suit_command_sequence_t;

/*
 * SUIT_Severable_Command_Sequence
 */
typedef struct suit_sev_command_sequence {
    union {
        suit_digest_t               digest;
        suit_command_sequence_t     cmd_seq;
    } value;
} suit_sev_command_sequence_t;

/*
 * SUIT_Common
 */
typedef struct suit_common {
    // TODO :                       suit-dependencies
    suit_components_t               components;
    // TODO :                       suit-dependency-components
    suit_command_sequence_t         cmd_seq;
} suit_common_t;

/*
 * SUIT_Manifest
 */
typedef struct suit_manifest {
    uint32_t                        version;
    uint32_t                        sequence_number;
    suit_common_t                   common;
    // TODO :                       suit-reference-uri
    // TODO :                       $$SUIT_Severable_Command_Sequences
    suit_sev_command_sequence_t     install;
    suit_command_sequence_t         validate;
    // TODO :                       $$SUIT_Command_Sequences
    // TODO :                       $$SUIT_Protected_Elements
} suit_manifest_t;

/*
 * SUIT_Authentication_Wrapper
 */
typedef struct suit_authentication_wrapper {
    size_t                          len;
    UsefulBufC                      auth_block[SUIT_MAX_ARRAY_LENGTH];
} suit_authentication_wrapper_t;

/*
 * SUIT_Envelope
 */
typedef struct suit_envelope {
    // TODO :                       suit-delegation
    suit_authentication_wrapper_t   wrapper;
    suit_manifest_t                 manifest;
    // TODO :                       SUIT_Severed_Fields
} suit_envelope_t;

int32_t suit_set_envelope(QCBORDecodeContext *context, suit_envelope_t *envelope);

#endif  // SUIT_MANIFEST_DATA_H
