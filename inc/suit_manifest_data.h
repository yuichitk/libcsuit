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
#include "t_cose/t_cose_common.h"

/*!
    \file   suit_manifest_data.h

    \brief  Declarations of structures and functions
 */

#define SUIT_MAX_ARRAY_LENGTH           20

#define SUIT_ENVELOPE_CBOR_TAG               107

typedef enum suit_envelope_key {
    SUIT_ENVELOPE_KEY_INVALID           = 0,
    SUIT_DELEGATION                     = 1,
    SUIT_AUTHENTICATION                 = 2,
    SUIT_MANIFEST                       = 3,
} suit_envelope_key_t;

typedef enum suit_algorithm_id {
    SUIT_ALGORITHM_ID_INVALID           = 0,
    SUIT_ALGORITHM_ID_SHA256            = -16, // cose-alg-sha-256
    SUIT_ALGORITHM_ID_SHAKE128          = -18, // cose-alg-shake128
    SUIT_ALGORITHM_ID_SHA384            = -43, // cose-alg-sha-384
    SUIT_ALGORITHM_ID_SHA512            = -44, // cose-alg-sha-512
    SUIT_ALGORITHM_ID_SHAKE256          = -45, // cose-alg-shake256
} suit_algorithm_id_t;

typedef enum suit_manifest_key {
    SUIT_MANIFEST_KEY_INVALID           = 0,
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
    SUIT_COSWID                         = 14,
} suit_manifest_key_t;

typedef enum suit_common_key {
    SUIT_COMMON_KEY_INVALID             = 0,
    SUIT_DEPENDENCIES                   = 1,
    SUIT_COMPONENTS                     = 2,
    SUIT_COMMON_SEQUENCE                = 4,
} suit_common_key_t;

typedef enum suit_dependency_key {
    SUIT_DEPENDENCY_INVALID             = 0,
    SUIT_DEPENDENCY_DIGEST              = 1,
    SUIT_DEPENDENCY_PREFIX              = 2,
} suit_dependency_key_t;

typedef enum suit_rep_policy_key {
    SUIT_CONDITION_INVALID              = 0,
    SUIT_CONDITION_VENDOR_IDENTIFIER    = 1,
    SUIT_CONDITION_CLASS_IDENTIFIER     = 2,
    SUIT_CONDITION_IMAGE_MATCH          = 3,
    SUIT_CONDITION_USE_BEFORE           = 4,
    SUIT_CONDITION_COMPONENT_SLOT       = 5,
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
    SUIT_DIRECTIVE_UNLINK               = 33,
} suit_rep_policy_key_t;

#define SUIT_SEVERABLE_INVALID               0 // 0b00000000
#define SUIT_SEVERABLE_IN_MANIFEST           1 // 0b00000001
#define SUIT_SEVERABLE_IN_ENVELOPE           2 // 0b00000010
#define SUIT_SEVERABLE_EXISTS              127 // 0b01111111
#define SUIT_SEVERABLE_IS_VERIFIED         128 // 0b10000000

typedef enum suit_wait_event_key {
    SUIT_WAIT_EVENT_AUTHORIZATION           = 1,
    SUIT_WAIT_EVENT_POWER                   = 2,
    SUIT_WAIT_EVENT_NETWORK                 = 3,
    SUIT_WAIT_EVENT_OTHER_DEVICE_VERSION    = 4,
    SUIT_WAIT_EVENT_TIME                    = 5,
    SUIT_WAIT_EVENT_TIME_OF_DAY             = 6,
    SUIT_WAIT_EVENT_DAY_OF_WEEK             = 7,
} suit_wait_event_key_t;

typedef enum suit_parameter_key {
    SUIT_PARAMETER_INVALID              = 0,
    SUIT_PARAMETER_VENDOR_IDENTIFIER    = 1,
    SUIT_PARAMETER_CLASS_IDENTIFIER     = 2,
    SUIT_PARAMETER_IMAGE_DIGEST         = 3,
    SUIT_PARAMETER_USE_BEFORE           = 4,
    SUIT_PARAMETER_COMPONENT_SLOT       = 5,

    SUIT_PARAMETER_STRICT_ORDER         = 12,
    SUIT_PARAMETER_SOFT_FAILURE         = 13,
    SUIT_PARAMETER_IMAGE_SIZE           = 14,

    SUIT_PARAMETER_ENCRYPTION_INFO      = 18,
    SUIT_PARAMETER_COMPRESSION_INFO     = 19,
    SUIT_PARAMETER_UNPACK_INFO          = 20,
    SUIT_PARAMETER_URI                  = 21,
    SUIT_PARAMETER_SOURCE_COMPONENT     = 22,
    SUIT_PARAMETER_RUN_ARGS             = 23,

    SUIT_PARAMETER_DEVICE_IDENTIFIER    = 24,
    SUIT_PARAMETER_MINIMUM_BATTERY      = 26,
    SUIT_PARAMETER_UPDATE_PRIORITY      = 27,
    SUIT_PARAMETER_VERSION              = 28,
    SUIT_PARAMETER_WAIT_INFO            = 29,
    SUIT_PARAMETER_URI_LIST             = 30,
} suit_parameter_key_t;

typedef enum suit_compression_info_key {
    SUIT_COMPRESSION_INVALID    = 0,
    SUIT_COMPRESSION_ALGORITHM  = 1,
} suit_compression_info_key_t;

typedef enum suit_compression_algorithm {
    SUIT_COMPRESSION_ALGORITHM_INVALID  = 0,
    SUIT_COMPRESSION_ALGORITHM_ZLIB     = 1,
    SUIT_COMPRESSION_ALGORITHM_BROTLI   = 2,
    SUIT_COMPRESSION_ALGORITHM_ZSTD     = 3,
} suit_compression_algorithm_t;

typedef struct suit_compression_info {
    suit_compression_algorithm_t    compression_algorithm;
    //TODO:                         $$SUIT_Compression_Info-extensions
} suit_compression_info_t;

typedef enum suit_unpack_info_key {
    SUIT_UNPACK_INVALID     = 0,
    SUIT_UNPACK_ALGORITHM   = 1,
} suit_unpack_info_key_t;

typedef enum suit_unpack_algorithm {
    SUIT_UNPACK_ALGORITHM_HEX   = 1,
    SUIT_UNPACK_ALGORITHM_ELF   = 2,
    SUIT_UNPACK_ALGORITHM_COFF  = 3,
    SUIT_UNPACK_ALGORITHM_SREC  = 4,
} suit_unpack_algorithm_t;

typedef enum suit_text_key {
    SUIT_TEXT_TYPE_INVALID          = 0,
    SUIT_TEXT_MANIFEST_DESCRIPTION  = 1,
    SUIT_TEXT_UPDATE_DESCRIPTION    = 2,
    SUIT_TEXT_MANIFEST_JSON_SOURCE  = 3,
    SUIT_TEXT_MANIFEST_YAML_SOURCE  = 4,
} suit_text_key;

typedef enum suit_text_component_key {
    SUIT_TEXT_CONTENT_INVALID       = 0,
    SUIT_TEXT_VENDOR_NAME           = 1,
    SUIT_TEXT_MODEL_NAME            = 2,
    SUIT_TEXT_VENDOR_DOMAIN         = 3,
    SUIT_TEXT_MODEL_INFO            = 4,
    SUIT_TEXT_COMPONENT_DESCRIPTION = 5,
    SUIT_TEXT_COMPONENT_VERSION     = 6,
    SUIT_TEXT_VERSION_REQUIRED      = 7,
} suit_text_component_key_t;

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
    suit_algorithm_id_t             algorithm_id;
    suit_buf_t                      bytes;
    // TODO :                       suit-digest-parameters
} suit_digest_t;

/*
 * SUIT_Component_Identifier
 */
typedef struct suit_component_identifier {
    size_t                          len;
    suit_buf_t                      identifier[SUIT_MAX_ARRAY_LENGTH];
} suit_component_identifier_t;

/*
 * SUIT_Components
 */
typedef struct suit_components {
    size_t                          len;
    suit_component_identifier_t     comp_id[SUIT_MAX_ARRAY_LENGTH];
} suit_components_t;


/*
 * SUIT_Dependency
 */
typedef struct suit_dependency {
    suit_digest_t                   digest;
    suit_component_identifier_t     prefix;
    //TODO:                         $$SUIT_Dependency-extensions
} suit_dependency_t;

/*
 * SUIT_Dependencies
 */
typedef struct suit_dependencies {
    size_t                          len;
    suit_dependency_t               dependency[SUIT_MAX_ARRAY_LENGTH];
} suit_dependencies_t;

/*
 * SUIT_Parameters
 */
typedef struct suit_parameters {
    uint64_t                        label;
    union {
        suit_buf_t                  string;
        int64_t                     int64;
        uint64_t                    uint64;
        bool                        isNull;
        suit_digest_t               digest;
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
    int64_t                         label;
    union {
        suit_buf_t                  string;
        int64_t                     int64;
        uint64_t                    uint64;
        bool                        isNull;
        suit_parameters_list_t      params_list;
    } value;
} suit_command_sequence_item_t;

/*
 * SUIT_Command_Sequence or SUIT_Common_Sequence
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
 * SUIT_Text_Component
 */
typedef struct suit_text_component {
    suit_buf_t  vendor_name;
    suit_buf_t  model_name;
    suit_buf_t  vendor_domain;
    suit_buf_t  model_info;
    suit_buf_t  component_description;
    suit_buf_t  component_version;
    suit_buf_t  version_required;
    // TODO :   $$suit-text-component-key-extensions
} suit_text_component_t;

typedef struct suit_text_component_pair {
    suit_component_identifier_t     key;
    suit_text_component_t           text_component;
} suit_text_component_pair_t;

/*
 * SUIT_Text
 */
typedef struct suit_text {
    size_t                      component_len;
    suit_text_component_pair_t  component[SUIT_MAX_ARRAY_LENGTH];
    suit_buf_t                  manifest_description;
    suit_buf_t                  update_description;
    suit_buf_t                  manifest_json_source;
    suit_buf_t                  manifest_yaml_source;
    // TODO :                   $$suit-text-key-extensions
} suit_text_t;

/*
 * SUIT_Authentication_Wrapper
 */
typedef struct suit_authentication_wrapper {
    suit_digest_t                   digest;
} suit_authentication_wrapper_t;

/*
 * SUIT_Severable_Manifest_Members
 */
typedef struct suit_severable_manifest_members {
    suit_command_sequence_t         dependency_resolution;
    uint8_t                         dependency_resolution_status;
    suit_command_sequence_t         payload_fetch;
    uint8_t                         payload_fetch_status;
    suit_command_sequence_t         install;
    uint8_t                         install_status;
    suit_text_t                     text;
    uint8_t                         text_status;
    suit_buf_t                      coswid;
    uint8_t                         coswid_status;
    // TODO :                       $$SUIT_severable-members-extension
} suit_severable_manifest_members_t;

/* SUIT_Severable_Members_Digests */
typedef struct suit_severable_members_digests {
    suit_digest_t                   dependency_resolution;
    suit_digest_t                   payload_fetch;
    suit_digest_t                   install;
    suit_digest_t                   text;
    suit_digest_t                   coswid;
    // TODO :                       $$severable-manifest-members-digests-extensions
} suit_severable_members_digests_t;

/* SUIT_Unseverable_Members */
typedef struct suit_unseverable_members {
    suit_command_sequence_t         validate;
    suit_command_sequence_t         load;
    suit_command_sequence_t         run;
    // TODO :                       $$unseverable-manifest-member-extensions
} suit_unseverable_members_t;

/*
 * SUIT_Common
 */
typedef struct suit_common {
    suit_dependencies_t             dependencies;
    suit_components_t               components;
    // TODO :                       suit-dependency-components
    suit_command_sequence_t         cmd_seq;
} suit_common_t;

/*
 * SUIT_Manifest
 */
typedef struct suit_manifest {
    bool                                is_verified;
    uint32_t                            version;
    uint32_t                            sequence_number;
    suit_common_t                       common;
    suit_buf_t                          reference_uri;
    suit_severable_manifest_members_t   sev_man_mem;
    suit_severable_members_digests_t    sev_mem_dig;
    suit_unseverable_members_t          unsev_mem;
} suit_manifest_t;

/*
 * SUIT_Envelope
 */
typedef struct suit_envelope {
    // TODO :                           suit-delegation
    suit_authentication_wrapper_t       wrapper;
    suit_manifest_t                     manifest;
    // TODO :                           SUIT_Severed_Fields
    /* SUIT_Severable_Manifest_Members */
    //suit_severable_manifest_members_t   sev_man_mem; //-> in manifest.sev_man_mem
} suit_envelope_t;

typedef struct suit_encode {
    UsefulBufC manifest;
    // SUIT_SeverableMembers
    UsefulBufC dependency_resolution;
    UsefulBufC payload_fetch;
    UsefulBufC install;
    UsefulBufC text;
    UsefulBufC coswid;

    uint8_t *buf;
    size_t pos;
    const size_t max_pos;
} suit_encode_t;

typedef struct t_cose_key t_cose_key;

suit_err_t suit_qcbor_get_next(QCBORDecodeContext *message, QCBORItem *item, uint8_t data_type);
suit_err_t suit_qcbor_get(QCBORDecodeContext *message, QCBORItem *item, bool next, uint8_t data_type);
size_t suit_qcbor_calc_rollback(QCBORItem *item);

/*!
    \brief Decode SUIT_Compression_Info.

    \param[in]  mode                Controls parsing behavior, e.g. #SUIT_DECODE_MODE_STRICT.
    \param[in]  buf                 Pointer and length of input byte string wrapped SUIT_Compression_Info.
    \param[out] compression_info    Pointer of output structure to hold the parsing result of SUIT_Compression_Info.

    \return     This returns one of the error codes defined by \ref suit_err_t.
 */
suit_err_t suit_decode_compression_info(uint8_t mode, const suit_buf_t *buf, suit_compression_info_t *compression_info);

/*!
    \brief  Decode SUIT binary.

    \param[in]  mode        This ontrols parsing behavior, e.g. #SUIT_DECODE_MODE_STRICT.
    \param[in]  buf         Pointer and length of input binary.
    \param[out] envelope    Pointer of output structure to hold the parsing result of SUIT binary.
    \param[in]  public_key  Pointer of public key to verify the COSE_Sign1 of authentication-wrapper.

    \return     This returns one of the error codes defined by \ref suit_err_t.
 */
suit_err_t suit_decode_envelope(uint8_t mode, suit_buf_t *buf, suit_envelope_t *envelope, const struct t_cose_key *public_key);

/*!
    \brief  Decode array of SUIT_Component_Identifier.

    \param[in]  mode        Controls parsing behavior, e.g. #SUIT_DECODE_MODE_STRICT.
    \param[in]  buf         Pointer and length of input binary.
    \param[out] identifier  Pointers and length of resulting SUIT_Component_Identifiers.

    \return     This returns one of the error codes defined by \ref suit_err_t.
 */
suit_err_t suit_decode_component_identifiers(uint8_t mode, suit_buf_t *buf, suit_component_identifier_t *identifier);

/*!
    \brief  Decode bstr-wrapped command sequence.

    \param[in]  mode        Controls parsing behavior, e.g. #SUIT_DECODE_MODE_STRICT.
    \param[in]  buf         Pointer and length of input binary.
    \param[out] identifier  Pointers and length of resulting SUIT_Command_Sequence.

    \return     This returns one of the error codes defined by \ref suit_err_t.
 */
suit_err_t suit_decode_command_sequence(uint8_t mode, const suit_buf_t *buf, suit_command_sequence_t *cmd_seq);


/*!
    \brief  Encode SUIT binary

    \param[in]      mode        Controls parsing behavior, e.g. #SUIT_DECODE_MODE_STRICT.
    \param[in]      envelope    Input struct of libcsuit, correspond to the SUIT_Envelope.
    \param[in]      signing_key The private key (or key pair) to generate COSE_Sign1 signature.
    \param[out]     buf         Output buffer of the binary.
    \param[in,out]  len         Length of the allocated buf size in input,
                                and the size of the generated binary size in output.

    \return     This returns one of the error codes defined by \ref suit_err_t.

    Encoding SUIT_Envelope takes several steps.
    1st. Generate SUIT_Digest of severed members
    2nd. Generate SUIT_Digest of suit-manifest
    3rd. Respectively append suit-authentication-wrapper, suit-manifest, ...

    This is the "map" of the encoding proccess.
    \code{.unparsed}
    SUIT_Envelope { // <= You are here!
        suit-authentication-wrapper,
        suit-manifest {
            suit-common,
            suit-install,
            suit-validate,
            ...
        }

        // severed member
        suit-install,
        suit-validate,
        ...
    }
    \endcode
 */
suit_err_t suit_encode_envelope(uint8_t mode, const suit_envelope_t *envelope, const t_cose_key *signing_key, uint8_t *buf, size_t *len);

#endif  // SUIT_MANIFEST_DATA_H
