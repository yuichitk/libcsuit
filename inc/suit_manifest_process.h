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

typedef uint8_t suit_condition_t;

typedef struct suit_install {
    suit_component_identifier_t component;

    /* image info */
    suit_buf_t                  vendor_id;
    suit_buf_t                  class_id;
    suit_digest_t               image_digest;
    uint64_t                    image_size;

    /* source info */
    suit_buf_t                  uri;
    uint64_t                    offset;

    /* condition info */
    suit_condition_t            condition_vendor_id;
    suit_condition_t            condition_class_id;
} suit_install_t;

/**
 * common commands for a specific component
 */
typedef struct suit_common_params {
    /* SUIT_Dependencies */
    //??

    /* SUIT_Components */
    suit_components_t           components;

    /* SUIT_Common_Sequence */
    struct {

        /* SUIT_Parameters */
        struct {
            suit_compression_info_t     compression_info;

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
    } common_commands;
} suit_common_params_t;

typedef struct suit_inputs {
    size_t manifest_len;
    suit_buf_t manifests[SUIT_MAX_ARRAY_LENGTH];
    size_t key_len;
    struct t_cose_key public_keys[SUIT_MAX_ARRAY_LENGTH];
} suit_inputs_t;

typedef struct suit_process {
    uint8_t mode;
    suit_inputs_t suit_inputs;
    suit_err_t (*suit_install)(suit_install_t *install);
} suit_process_t;

void suit_process_digest(QCBORDecodeContext *context, suit_digest_t *digest);
suit_err_t suit_process_authentication_wrapper(QCBORDecodeContext *context, suit_inputs_t *suit_inputs, suit_digest_t *digest);
suit_err_t suit_process_envelopes(suit_process_t *suit_process);

#endif /* SUIT_MANIFEST_PROCESS_H */


