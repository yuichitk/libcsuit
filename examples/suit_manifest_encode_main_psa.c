/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 * Copyright (c) 2021 Arm Ltd. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#if defined(LIBCSUIT_PSA_CRYPTO_C)

#include <stdio.h>
#include "qcbor/qcbor.h"
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_manifest_print.h"
#include "suit_cose.h"
#include "suit_examples_common.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "psa/crypto.h"

/* ECC private key (P256r1) */
static const uint8_t private_key[] =
    {
    0x49, 0xc9, 0xa8, 0xc1, 0x8c, 0x4b, 0x88, 0x56,
    0x38, 0xc4, 0x31, 0xcf, 0x1d, 0xf1, 0xc9, 0x94,
    0x13, 0x16, 0x09, 0xb5, 0x80, 0xd4, 0xfd, 0x43,
    0xa0, 0xca, 0xb1, 0x7d, 0xb2, 0xf1, 0x3e, 0xee,
    };

static const size_t private_key_len = sizeof(private_key);

#define MAX_BUFFER_SIZE 2000

int main(int argc, char *argv[])
{
    struct t_cose_key    key_pair;
    psa_key_type_t       key_type;
    psa_status_t         result;
    psa_key_handle_t     key_handle;
    psa_algorithm_t      key_alg;
    uint8_t              encode_buf[MAX_BUFFER_SIZE];
    size_t               encode_len = MAX_BUFFER_SIZE;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    suit_envelope_t      envelope = (suit_envelope_t){ 0 };
    suit_manifest_t     *manifest = &envelope.manifest;

    // Generate manifest
    manifest->version = 1;
    manifest->sequence_number = 2;

    uint8_t component_id[] = {0x00};
    suit_common_t *common = &manifest->common;
    common->components.len = 1;
    common->components.comp_id[0].len = 1;
    common->components.comp_id[0].identifier[0] = (suit_buf_t){.ptr = component_id, .len = sizeof(component_id)};

    uint8_t vendor_id[] = {0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE};
    uint8_t class_id[] = {0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48, 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45};
    suit_command_sequence_t *cmd_seq = &common->cmd_seq;
    cmd_seq->len = 3;

    cmd_seq->commands[0].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    suit_parameters_list_t *params_list = &cmd_seq->commands[0].value.params_list;
    params_list->len = 4;

    params_list->params[0].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    params_list->params[0].value.string.ptr = vendor_id;
    params_list->params[0].value.string.len = sizeof(vendor_id);

    params_list->params[1].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    params_list->params[1].value.string.ptr = class_id;
    params_list->params[1].value.string.len = sizeof(class_id);

    uint8_t image_digest[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    params_list->params[2].label = SUIT_PARAMETER_IMAGE_DIGEST,
    params_list->params[2].value.digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    params_list->params[2].value.digest.bytes.ptr = image_digest;
    params_list->params[2].value.digest.bytes.len = sizeof(image_digest);

    params_list->params[3].label = SUIT_PARAMETER_IMAGE_SIZE;
    params_list->params[3].value.uint64 = 34768;

    cmd_seq->commands[1].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
    cmd_seq->commands[1].value.uint64 = 15;

    cmd_seq->commands[2].label = SUIT_CONDITION_CLASS_IDENTIFIER;
    cmd_seq->commands[2].value.uint64 = 15;

    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &manifest->sev_man_mem.install;
    install->len = 3;
    install->commands[0].label = SUIT_DIRECTIVE_SET_PARAMETERS;
    params_list = &install->commands[0].value.params_list;
    params_list->len = 1;

    uint8_t uri[] = "http://example.com/file.bin";
    params_list->params[0].label = SUIT_PARAMETER_URI;
    params_list->params[0].value.string.ptr = uri;
    params_list->params[0].value.string.len = sizeof(uri) - 1;

    install->commands[1].label = SUIT_DIRECTIVE_FETCH;
    install->commands[1].value.uint64 = 15;

    install->commands[2].label = SUIT_CONDITION_IMAGE_MATCH;
    install->commands[2].value.uint64 = 15;

    suit_command_sequence_t *validate = &manifest->unsev_mem.validate;
    validate->len = 1;
    validate->commands[0].label = SUIT_CONDITION_IMAGE_MATCH;
    validate->commands[0].value.uint64 = 15;

    key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1);
    key_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

    result = psa_crypto_init();

    if(result != PSA_SUCCESS)
        return( EXIT_FAILURE );

    psa_set_key_usage_flags( &key_attributes, PSA_KEY_USAGE_SIGN_HASH |
                                              PSA_KEY_USAGE_VERIFY_HASH |
                                              PSA_KEY_USAGE_EXPORT );
    psa_set_key_algorithm( &key_attributes, key_alg );
    psa_set_key_type( &key_attributes, key_type );

    result = psa_import_key(&key_attributes,
                            private_key,
                            private_key_len,
                            &key_handle);

    if (result != PSA_SUCCESS)
        return( EXIT_FAILURE );

    key_pair.k.key_handle = key_handle;
    key_pair.crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    result = suit_encode_envelope(&envelope, &key_pair, encode_buf, &encode_len);
    if (result != SUIT_SUCCESS) {
        printf("Fail to encode. %d\n", result);
        return( EXIT_FAILURE );
    }

    printf("\nSUIT Manifest.\n");
    suit_print_hex(encode_buf, encode_len);

    psa_destroy_key( key_handle );

    return( EXIT_SUCCESS );
}
#endif /* LIBCSUIT_PSA_CRYPTO_C */
