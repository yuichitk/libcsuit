/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_PROCESS_H
#define SUIT_MANIFEST_PROCESS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_common.h"
#include "suit_manifest_data.h"

/*!
    \file   suit_manifest_process.h

    \brief  Declarations of structures and functions
 */

#define BIT(nr) (1UL << (nr))
#define SUIT_PARAMETER_CONTAINS_VENDOR_IDENTIFIER BIT(SUIT_PARAMETER_VENDOR_IDENTIFIER)
#define SUIT_PARAMETER_CONTAINS_URI BIT(SUIT_PARAMETER_URI)

typedef struct suit_on_error_args {
    suit_envelope_key_t level0;
    union {
        suit_manifest_key_t manifest_key;
    } level1;
    union {
        suit_rep_policy_key_t condition_directive;
        suit_text_key_t text_key;
    } level2;
    union {
        suit_parameter_key_t parameter;
        suit_text_component_key_t text_component_key;
    } level3;

    QCBORError qcbor_error;
    suit_err_t suit_error;
} suit_on_error_args_t;

typedef struct suit_install_args {
    uint64_t                    command_exists;

    uint64_t                    manifest_sequence_number;

    const suit_component_identifier_t *component;

    /* image info */
    suit_buf_t                  vendor_id;
    suit_buf_t                  class_id;
    suit_digest_t               image_digest;
    uint64_t                    image_size;

    /* source info */
    suit_buf_t                  uri;
    uint64_t                    offset;

    /* condition info */
    struct {
        uint64_t                vendor_id;
        uint64_t                class_id;
    } condition;
} suit_install_args_t;

/**
 * common commands for a specific component
 */
typedef struct suit_common_args {
    uint64_t                    manifest_sequence_number;

    /* SUIT_Dependencies */
    //??

    /* SUIT_Components */
    suit_components_t           components;

    /* SUIT_Common_Sequence */
    /* SUIT_Conditions */
    struct {
        uint64_t                    vendor_identifier;
        uint64_t                    class_identifier;
        uint64_t                    image_match;
        uint64_t                    use_before;
        uint64_t                    component_offset;
        uint64_t                    abort;
        uint64_t                    device_identifier;
        uint64_t                    image_not_match;
        uint64_t                    minimum_battery;
        uint64_t                    update_authorized;
        uint64_t                    version;
    } condition;

    /* SUIT_Directives */
    struct {
        uint64_t                    directive_exists;
    } directive;

    /* SUIT_Parameters */
    struct {
        uint64_t                    exists;

        suit_buf_t                  vendor_id;
        suit_buf_t                  class_id;
        suit_digest_t               image_digest;
        uint64_t                    image_size;
        uint64_t                    use_before;

        suit_encryption_info_t      encryption_info;
        suit_compression_info_t     compression_info;
        suit_unpack_info_t          unpack_info;

        /* uri is combined in uri-list */
        //suit_buf_t                uri;

        //??                        source_component;

        /* used in suit-directive-run */
        suit_buf_t                  run_args;

        /* positive minimum battery level in mWh */
        int64_t                     minimum_battery;

        /* the value is not defined, though 0 means "NOT GIVEN" here */
        int64_t                     update_priority;

        /* processed if suit-condition-version is specified */
        suit_buf_t                  version;

        //??                        wait_info;

        /* decoded from both suit-parameter-uri and suit-parameter-uri-list,
           and will be used one-by-one with its array order */
        suit_buf_t                  uri_list[SUIT_MAX_ARRAY_LENGTH];

        //??                        fetch_arguments;

        /* default True */
        suit_parameter_bool_t       strict_order;

        /* default True if suit-directive-try-each is involved,
           default False if suit-directive-run-sequence is invoked */
        suit_parameter_bool_t       soft_failure;
    } parameter;

    /* SUIT_Digest of severed members */
    struct {
        suit_digest_t dependency_resolution;
        suit_digest_t payload_fetch;
        suit_digest_t install;
        suit_digest_t text;
        suit_digest_t coswid;
    } signatures;
} suit_common_args_t;

typedef struct suit_inputs {
    size_t manifest_len;
    suit_buf_t manifests[SUIT_MAX_ARRAY_LENGTH];
    size_t key_len;
    struct t_cose_key public_keys[SUIT_MAX_ARRAY_LENGTH];
} suit_inputs_t;

typedef struct suit_process {
    uint8_t mode;
    suit_inputs_t suit_inputs;
    suit_err_t (*suit_install)(suit_install_args_t *install);
    suit_err_t (*suit_on_error)(suit_on_error_args_t *error);
} suit_process_t;

void suit_process_digest(QCBORDecodeContext *context, suit_digest_t *digest);
suit_err_t suit_process_authentication_wrapper(QCBORDecodeContext *context, suit_inputs_t *suit_inputs, suit_digest_t *digest);

/*!
    \brief  Decode & Process SUIT binary

    \param[in]      suit_process    Input struct of libcsuit including manifests, public keys, callback functions, etc.

    \return         This returns one of the error codes defined by \ref suit_err_t.

    Process one or more SUIT_Envelope(s) like below.
    Libcsuit call suit_install, suit_run, ... indicated by function pointers in suit_process.
    If any error occurred, on_error callback function will be called if set.

    \code{.unparsed}
    +-App---------------------------+
    | main() {                      |
    |   prepare_keys();             |
    |   create_suit_process();      |
    |   while {                     |
    |     fetch_manifests();        |
    |     update_suit_process();    |    +-libcsuit------------------------+
    |     suit_process_envelopes(); |===>| suit_process_envelops() {       |
    |   }                           |    |   decode_and_check_digests();   |
    | }                             |    |   for (m in manifests) {        |
    |                               |    |     decode_common(m);           |
    | install_callback() {          |<===|     decode_and_call_install(m); |
    |   get_image(uri, ptr);        |    |     (wait)                      |
    |   return SUIT_SUCCESS;        |===>|     if (!install_success)       |
    | }                             |    |       return SUIT_ERR_FATAL;    |
    | error_callback() {            |    |     check_image_digest(m, ptr)  |
    |   // do something             |    |     ...                         |
    |   if (fatal)                  |    |   }                             |
    |     return SUIT_ERR_FATAL;    |    | }                               |
    |   return SUIT_SUCCESS;        |    +---------------------------------+
    | }                             |
    +-------------------------------+
    \endcode
 */
suit_err_t suit_process_envelopes(suit_process_t *suit_process);

#endif /* SUIT_MANIFEST_PROCESS_H */


