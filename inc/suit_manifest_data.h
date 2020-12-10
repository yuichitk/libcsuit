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
} suit_envelope_key_t;

typedef enum suit_algorithm_id {
    SUIT_INVALID_ALGORITHM_ID           = 0,
    SUIT_ALGORITHM_ID_SHA224            = 1,
    SUIT_ALGORITHM_ID_SHA256            = 2,
    SUIT_ALGORITHM_ID_SHA384            = 3,
    SUIT_ALGORITHM_ID_SHA512            = 4,
    SUIT_ALGORITHM_ID_SHA3_224          = 5,
    SUIT_ALGORITHM_ID_SHA3_256          = 6,
    SUIT_ALGORITHM_ID_SHA3_384          = 7,
    SUIT_ALGORITHM_ID_SHA3_512          = 8,
} suit_algorithm_id_t;

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

typedef enum suit_common_key {
    SUIT_INVALID_COMMON_KEY             = 0,
    SUIT_DEPENDENCIES                   = 1,
    SUIT_COMPONENTS                     = 2,
    SUIT_COMMON_SEQUENCE                = 4,
} suit_common_key_t;

typedef enum suit_dependency_key {
    SUIT_INVALID_DEPENDENCY             = 0,
    SUIT_DEPENDENCY_DIGEST              = 1,
    SUIT_DEPENDENCY_PREFIX              = 2,
} suit_dependency_key_t;

typedef enum suit_rep_policy_key {
    SUIT_INVALID_CONDITION              = 0,
    SUIT_CONDITION_VENDOR_IDENTIFIER    = 1,
    SUIT_CONDITION_CLASS_IDENTIFIER     = 2,
    SUIT_CONDITION_IMAGE_MATCH          = 3,
    SUIT_CONDITION_USE_BEFORE           = 4,
    SUIT_CONDITION_COMPONENT_OFFSET     = 5,
    SUIT_CONDITION_ABORT                = 14,
    SUIT_CONDITION_DEVICE_IDENTIFIER    = 24,
    SUIT_CONDITION_IMAGE_NOT_MATCH      = 25,
    SUIT_CONDITION_MINIMUM_BATTERY      = 26,
    SUIT_CONDITION_UPDATE_AUTHORIZED    = 27,
    SUIT_CONDITION_VERSION              = 28,

    SUIT_DIRECTIVE_SET_COMPONENT_INDEX  = 12,
    SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX = 13,
    SUIT_DIRECTIVE_TRY_EACH             = 15,
    SUIT_DIRECTIVE_DO_EACH              = 16,
    SUIT_DIRECTIVE_MAP_FILTER           = 17,
    SUIT_DIRECTIVE_PROCESS_DEPENDENCY   = 18,
    SUIT_DIRECTIVE_SET_PARAMETERS       = 19,
    SUIT_DIRECTIVE_OVERRIDE_PARAMETERS  = 20,
    SUIT_DIRECTIVE_FETCH                = 21,
    SUIT_DIRECTIVE_COPY                 = 22,
    SUIT_DIRECTIVE_RUN                  = 23,
    SUIT_DIRECTIVE_WAIT                 = 29,
    SUIT_DIRECTIVE_FETCH_URI_LIST       = 30,
    SUIT_DIRECTIVE_SWAP                 = 31,
    SUIT_DIRECTIVE_RUN_SEQUENCE         = 32,
} suit_rep_policy_key_t;


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
