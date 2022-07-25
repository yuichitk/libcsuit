/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_common.h"
#include "csuit/suit_common.h"
#include "csuit/suit_manifest_data.h"
#include "csuit/suit_cose.h"
#include "csuit/suit_digest.h"
#define SUIT_ENCODE_MAX_BUFFER_SIZE 4096 * 2
#define SUIT_ENCODE_MAX_ENCODE_ITEM_SIZE 64

/*!
    \file   suit_manifest_encode.c

    \brief  This implements libcsuit encoding

    Prepare suit_eocode_t struct and suit_keys_t,
    and then call suit_encode_envelope() to encode whole SUIT manifest.
 */

suit_err_t suit_encode_append_severed_members(const suit_encode_t *suit_encode, QCBOREncodeContext *context) {
    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->dependency_resolution)
        && suit_encode->dependency_resolution_digest.bytes.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_DEPENDENCY_RESOLUTION, suit_encode->dependency_resolution);
    }
    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->payload_fetch)
        && suit_encode->payload_fetch_digest.bytes.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_PAYLOAD_FETCH, suit_encode->payload_fetch);
    }
    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->install)
        && suit_encode->install_digest.bytes.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_INSTALL, suit_encode->install);
    }
    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->text)
        && suit_encode->text_digest.bytes.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_TEXT, suit_encode->text);
    }
    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->coswid)
        && suit_encode->coswid_digest.bytes.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_COSWID, suit_encode->coswid);
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_encode_append_manifest(const suit_encode_t *suit_encode, QCBOREncodeContext *context) {
    QCBOREncode_AddBytesToMapN(context, SUIT_MANIFEST, suit_encode->manifest);
    return SUIT_SUCCESS;
}

suit_err_t suit_encode_append_digest(const suit_digest_t *digest, const uint32_t label, QCBOREncodeContext *context) {
    if (label > 0) {
        /* in map */
        QCBOREncode_OpenArrayInMapN(context, label);
    }
    else {
        QCBOREncode_OpenArray(context);
    }
    QCBOREncode_AddInt64(context, digest->algorithm_id);
    QCBOREncode_AddBytes(context, (UsefulBufC){.ptr = digest->bytes.ptr, .len = digest->bytes.len});
    QCBOREncode_CloseArray(context);
    return SUIT_SUCCESS;
}

suit_err_t suit_encode_digest(const suit_digest_t *digest, suit_encode_t *suit_encode, UsefulBuf *buf) {
    QCBOREncodeContext context;
    UsefulBuf tmp_buf;
    suit_err_t result = suit_use_suit_encode_buf(suit_encode, 0, &tmp_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBOREncode_Init(&context, tmp_buf);
    suit_encode_append_digest(digest, 0, &context);
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return suit_fix_suit_encode_buf(suit_encode, t_buf.len);
}

suit_err_t suit_generate_digest_include_header(const uint8_t *ptr, const size_t len, suit_encode_t *suit_encode, suit_digest_t *digest) {
    suit_err_t result = SUIT_SUCCESS;
    UsefulBuf tmp_buf;
    result = suit_use_suit_encode_buf(suit_encode, 0, &tmp_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, tmp_buf);
    QCBOREncode_AddBytes(&context, (UsefulBufC){.ptr = ptr, .len = len});
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    result = suit_fix_suit_encode_buf(suit_encode, t_buf.len);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    return suit_generate_digest(t_buf.ptr, t_buf.len, suit_encode, digest);
}

suit_err_t suit_generate_encoded_digest(const uint8_t *ptr, const size_t len, suit_encode_t *suit_encode, UsefulBuf *buf) {
    suit_err_t result = SUIT_SUCCESS;

    suit_digest_t digest;
    digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    UsefulBuf tmp_buf;
    result = suit_use_suit_encode_buf(suit_encode, SHA256_DIGEST_LENGTH, &tmp_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    digest.bytes.ptr = tmp_buf.ptr;
    digest.bytes.len = tmp_buf.len;
    result = suit_fix_suit_encode_buf(suit_encode, digest.bytes.len);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    result = suit_generate_digest_include_header(ptr, len, suit_encode, &digest);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    result = suit_encode_digest(&digest, suit_encode, buf);

    return result;
}

suit_err_t suit_encode_append_payloads(uint8_t mode, const suit_envelope_t *envelope, QCBOREncodeContext *context) {
    for (size_t i = 0; i < envelope->payloads.len; i++) {
        QCBOREncode_AddBytesToMap(context, envelope->payloads.payload[i].key.ptr, envelope->payloads.payload[i].bytes);
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_encode_append_authentication_wrapper(uint8_t mode, UsefulBufC digest, UsefulBuf signatures[], size_t num_signature, QCBOREncodeContext *context)
{
    QCBOREncode_BstrWrapInMapN(context, SUIT_AUTHENTICATION);
    QCBOREncode_OpenArray(context);
    QCBOREncode_AddBytes(context, digest);
    for (size_t i = 0; i < num_signature; i++) {
        QCBOREncode_AddBytes(context, UsefulBuf_Const(signatures[i]));
    }
    QCBOREncode_CloseArray(context);
    QCBOREncode_CloseBstrWrap(context, NULL);
    return SUIT_SUCCESS;
}

suit_err_t suit_append_directive_override_parameters(const suit_parameters_list_t *params_list, suit_encode_t *suit_encode, QCBOREncodeContext *context) {
    QCBOREncode_OpenMap(context);
    suit_err_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        const suit_parameters_t *item = &params_list->params[i];
        switch (item->label) {
            case SUIT_PARAMETER_COMPONENT_SLOT:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                QCBOREncode_AddUInt64ToMapN(context, item->label, item->value.uint64);
                break;
            case SUIT_PARAMETER_URI:
                if (item->value.string.len > 0) {
                    QCBOREncode_AddTextToMapN(context, item->label, (UsefulBufC){.ptr = item->value.string.ptr, .len = item->value.string.len});
                }
                else {
                    QCBOREncode_AddNULLToMapN(context, item->label);
                }
                break;
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
            case SUIT_PARAMETER_COMPRESSION_INFO:
                QCBOREncode_AddBytesToMapN(context, item->label, (UsefulBufC){.ptr = item->value.string.ptr, .len = item->value.string.len});
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                QCBOREncode_BstrWrapInMapN(context, item->label);
                result = suit_encode_append_digest(&item->value.digest, 0, context);
                QCBOREncode_CloseBstrWrap(context, NULL);
                if (result != SUIT_SUCCESS) {
                    break;
                }
                break;
            case SUIT_PARAMETER_USE_BEFORE:

            case SUIT_PARAMETER_STRICT_ORDER:
            case SUIT_PARAMETER_SOFT_FAILURE:

            case SUIT_PARAMETER_ENCRYPTION_INFO:
            case SUIT_PARAMETER_UNPACK_INFO:
            case SUIT_PARAMETER_RUN_ARGS:

            case SUIT_PARAMETER_DEVICE_IDENTIFIER:
            case SUIT_PARAMETER_MINIMUM_BATTERY:
            case SUIT_PARAMETER_UPDATE_PRIORITY:
            case SUIT_PARAMETER_VERSION:
            case SUIT_PARAMETER_WAIT_INFO:
            case SUIT_PARAMETER_URI_LIST:
            default:
                result = SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (result != SUIT_SUCCESS) {
            break;
        }
    }
    QCBOREncode_CloseMap(context);
    return result;
}

suit_err_t suit_encode_common_sequence(suit_command_sequence_t *cmd_seq, suit_encode_t *suit_encode, UsefulBuf *buf) {
    suit_err_t result = SUIT_SUCCESS;
    UsefulBuf tmp_buf;
    result = suit_use_suit_encode_buf(suit_encode, 0, &tmp_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, tmp_buf);
    QCBOREncode_OpenArray(&context);
    for (size_t i = 0; i < cmd_seq->len; i++) {
        const suit_command_sequence_item_t *item = &cmd_seq->commands[i];
        if (item->label == SUIT_CONDITION_INVALID) {
            continue;
        }
        switch (item->label) {
            case SUIT_CONDITION_VENDOR_IDENTIFIER:
            case SUIT_CONDITION_CLASS_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_MATCH:
            case SUIT_CONDITION_COMPONENT_SLOT:
            case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
            case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
            case SUIT_DIRECTIVE_FETCH:
            case SUIT_DIRECTIVE_COPY:
            case SUIT_DIRECTIVE_RUN:
            case SUIT_DIRECTIVE_UNLINK:
                QCBOREncode_AddUInt64(&context, item->label);
                QCBOREncode_AddUInt64(&context, item->value.uint64);
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                QCBOREncode_AddUInt64(&context, item->label);
                result = suit_append_directive_override_parameters(&item->value.params_list, suit_encode, &context);
                break;
            case SUIT_DIRECTIVE_TRY_EACH:
                QCBOREncode_AddUInt64(&context, item->label);
                QCBOREncode_OpenArray(&context);
                for (size_t j = i; j < cmd_seq->len; j++) {
                    if (cmd_seq->commands[j].label != SUIT_DIRECTIVE_TRY_EACH) {
                        continue;
                    }
                    QCBOREncode_AddBytes(&context, (UsefulBufC){.ptr = cmd_seq->commands[j].value.string.ptr, .len = cmd_seq->commands[j].value.string.len});
                    cmd_seq->commands[j].label = SUIT_CONDITION_INVALID;;
                }
                QCBOREncode_CloseArray(&context);
                break;
            case SUIT_CONDITION_USE_BEFORE:
            case SUIT_CONDITION_ABORT:
            case SUIT_CONDITION_DEVICE_IDENTIFIER:
            case SUIT_CONDITION_IMAGE_NOT_MATCH:
            case SUIT_CONDITION_MINIMUM_BATTERY:
            case SUIT_CONDITION_UPDATE_AUTHORIZED:
            case SUIT_CONDITION_VERSION:

            case SUIT_DIRECTIVE_DO_EACH:
            case SUIT_DIRECTIVE_MAP_FILTER:
            case SUIT_DIRECTIVE_WAIT:
            case SUIT_DIRECTIVE_FETCH_URI_LIST:
            case SUIT_DIRECTIVE_SWAP:
            case SUIT_DIRECTIVE_RUN_SEQUENCE:
            default:
                result = SUIT_ERR_NOT_IMPLEMENTED;
        }
    }
    QCBOREncode_CloseArray(&context);
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return suit_fix_suit_encode_buf(suit_encode, t_buf.len);
}

suit_err_t suit_encode_append_component_identifier(const suit_component_identifier_t *component_id, uint32_t label, QCBOREncodeContext *context) {
    if (label > 0) {
        QCBOREncode_OpenArrayInMapN(context, label);
    }
    else {
        QCBOREncode_OpenArray(context);
    }
    for (size_t j = 0; j < component_id->len; j++) {
        const suit_buf_t *identifier = &component_id->identifier[j];
        QCBOREncode_AddBytes(context, (UsefulBufC){.ptr = identifier->ptr, .len = identifier->len});
    }
    QCBOREncode_CloseArray(context);
    return SUIT_SUCCESS;
}

suit_err_t suit_encode_common(const suit_common_t *suit_common, suit_encode_t *suit_encode, UsefulBuf *buf) {
    UsefulBuf suit_common_sequence_buf;
    suit_err_t result = suit_encode_common_sequence((suit_command_sequence_t *)&suit_common->cmd_seq, suit_encode, &suit_common_sequence_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    UsefulBuf suit_common_buf;
    result = suit_use_suit_encode_buf(suit_encode, 0, &suit_common_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBOREncodeContext context;
    QCBOREncode_Init(&context, suit_common_buf);
    QCBOREncode_OpenMap(&context);

    // suit-dependencies
    if (suit_common->dependencies.len > 0) {
        QCBOREncode_OpenArrayInMapN(&context, SUIT_DEPENDENCIES);
        for (size_t i = 0; i <suit_common->dependencies.len; i++) {
            const suit_dependency_t *dependency = &suit_common->dependencies.dependency[i];
            QCBOREncode_OpenMap(&context);
            suit_encode_append_digest(&dependency->digest, SUIT_DEPENDENCY_DIGEST, &context);
            if (dependency->prefix.len > 0) {
                suit_encode_append_component_identifier(&dependency->prefix, SUIT_DEPENDENCY_PREFIX, &context);
            }
            //TODO: SUIT_Dependency-extensions
            QCBOREncode_CloseMap(&context);
        }
        QCBOREncode_CloseArray(&context);
    }

    // suit-components
    if (suit_common->components.len > 0) {
        QCBOREncode_OpenArrayInMapN(&context, SUIT_COMPONENTS);
        for (size_t i = 0; i < suit_common->components.len; i++) {
            suit_encode_append_component_identifier(&suit_common->components.comp_id[i], 0, &context);
        }
        QCBOREncode_CloseArray(&context);
    }

    // suit-common-sequence
    if (suit_common_sequence_buf.len > 0) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_COMMON_SEQUENCE, UsefulBuf_Const(suit_common_sequence_buf));
    }

    QCBOREncode_CloseMap(&context);
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    result = suit_fix_suit_encode_buf(suit_encode, t_buf.len);
    return result;
}

suit_err_t suit_encode_text(const suit_text_t *text, suit_encode_t *suit_encode, UsefulBuf *buf) {
    suit_err_t result;
    UsefulBuf tmp_buf;
    result = suit_use_suit_encode_buf(suit_encode, 0, &tmp_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, tmp_buf);

    QCBOREncode_OpenMap(&context);
    // SUIT_Text_Keys : tstr
    if (text->manifest_description.len > 0) {
        QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_MANIFEST_DESCRIPTION, (UsefulBufC){.ptr = text->manifest_description.ptr, .len = text->manifest_description.len});
    }
    if (text->update_description.len > 0) {
        QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_MANIFEST_DESCRIPTION, (UsefulBufC){.ptr = text->update_description.ptr, .len = text->manifest_description.len});
    }
    if (text->manifest_json_source.len > 0) {
        QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_MANIFEST_DESCRIPTION, (UsefulBufC){.ptr = text->manifest_json_source.ptr, .len = text->manifest_description.len});
    }
    if (text->manifest_yaml_source.len > 0) {
        QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_MANIFEST_DESCRIPTION, (UsefulBufC){.ptr = text->manifest_yaml_source.ptr, .len = text->manifest_description.len});
    }
    // TODO suit-text-key-extensions

    // SUIT_Component_Identifier : {}
    for (size_t i = 0; i < text->component_len; i++) {
        const suit_component_identifier_t *component = &text->component[i].key;
        QCBOREncode_OpenArray(&context);
        for (size_t j = 0; j < component->len; j++) {
            QCBOREncode_AddBytes(&context, (UsefulBufC){.ptr = component->identifier[j].ptr, .len = component->identifier[j].len});
        }
        QCBOREncode_CloseArray(&context);
        QCBOREncode_OpenMap(&context);
        const suit_text_component_t *text_component = &text->component[i].text_component;
        if (text_component->vendor_name.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_VENDOR_NAME, (UsefulBufC){.ptr = text_component->vendor_name.ptr, .len = text_component->vendor_name.len});
        }
        if (text_component->model_name.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_MODEL_NAME, (UsefulBufC){.ptr = text_component->model_name.ptr, .len = text_component->model_name.len});
        }
        if (text_component->vendor_domain.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_VENDOR_DOMAIN, (UsefulBufC){.ptr = text_component->vendor_domain.ptr, .len = text_component->vendor_domain.len});
        }
        if (text_component->model_info.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_MODEL_INFO, (UsefulBufC){.ptr = text_component->model_info.ptr, .len = text_component->model_info.len});
        }
        if (text_component->component_description.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_COMPONENT_DESCRIPTION, (UsefulBufC){.ptr = text_component->component_description.ptr, .len = text_component->component_description.len});
        }
        if (text_component->component_version.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_COMPONENT_VERSION, (UsefulBufC){.ptr = text_component->component_version.ptr, .len = text_component->component_version.len});
        }
        if (text_component->version_required.len > 0) {
            QCBOREncode_AddTextToMapN(&context, SUIT_TEXT_VERSION_REQUIRED, (UsefulBufC){.ptr = text_component->version_required.ptr, .len = text_component->version_required.len});
        }
        // TODO suit-text-component-key-extensions
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseMap(&context);

    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return suit_fix_suit_encode_buf(suit_encode, t_buf.len);
}

suit_err_t suit_encode_text_bstr(const suit_text_t *text, suit_encode_t *suit_encode, UsefulBuf *buf) {
    suit_err_t result = SUIT_SUCCESS;
    UsefulBuf text_buf;
    result = suit_encode_text(text, suit_encode, &text_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    UsefulBuf tmp_buf;
    result = suit_use_suit_encode_buf(suit_encode, 0, &tmp_buf);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBOREncodeContext context;
    QCBOREncode_Init(&context, *buf);
    QCBOREncode_AddBytes(&context, (UsefulBufC){.ptr = tmp_buf.ptr, .len = tmp_buf.len});
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return suit_fix_suit_encode_buf(suit_encode, t_buf.len);
}

/*!
    \brief  Encode suit-manifest

    \param[in]  envelope    Input struct of libcsuit, correspond to the SUIT_Envelope.
    \param[out] suit_encode Internal struct holding the status of encoding binary.

    \return     This returns one of the error codes defined by \ref suit_err_t.

    This is the "map" of the encoding process.
    \code{.unparsed}
    SUIT_Envelope {
        suit-authentication-wrapper,
        suit-manifest { // <= You are here!
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
suit_err_t suit_encode_manifest(const suit_envelope_t *envelope, suit_encode_t *suit_encode) {
    /*
     * Encode each bstr wrapped element first
     * and then create whole manifest file,
     * because some elements would be taken their digests
     */
    const suit_manifest_t *manifest = &envelope->manifest;
    UsefulBuf suit_common = NULLUsefulBuf;
    suit_err_t result = suit_encode_common(&manifest->common, suit_encode, &suit_common);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* encode unseverable members */
    UsefulBuf validate_buf = NULLUsefulBuf;
    if (manifest->unsev_mem.validate.len > 0) {
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->unsev_mem.validate, suit_encode, &validate_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    UsefulBuf load_buf = NULLUsefulBuf;
    if (manifest->unsev_mem.load.len > 0) {
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->unsev_mem.load, suit_encode, &load_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    UsefulBuf run_buf = NULLUsefulBuf;
    if (manifest->unsev_mem.run.len > 0) {
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->unsev_mem.run, suit_encode, &run_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }

    /* encode severable members */
    if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_EXISTS) {
        UsefulBuf dependency_resolution_buf = NULLUsefulBuf;
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.dependency_resolution, suit_encode, &dependency_resolution_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        suit_encode->dependency_resolution = UsefulBuf_Const(dependency_resolution_buf);

        if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_ENVELOPE) {
            suit_digest_t *dependency_resolution_digest = &suit_encode->dependency_resolution_digest;
            result = suit_generate_digest_include_header(suit_encode->dependency_resolution.ptr, suit_encode->dependency_resolution.len, suit_encode, dependency_resolution_digest);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
    }

    if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_EXISTS) {
        UsefulBuf payload_fetch_buf = NULLUsefulBuf;
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.payload_fetch, suit_encode, &payload_fetch_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        suit_encode->payload_fetch = UsefulBuf_Const(payload_fetch_buf);

        if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_ENVELOPE) {
            suit_digest_t *payload_fetch_digest = &suit_encode->payload_fetch_digest;
            result = suit_generate_digest_include_header(suit_encode->payload_fetch.ptr, suit_encode->payload_fetch.len, suit_encode, payload_fetch_digest);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
    }

    if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_EXISTS) {
        UsefulBuf install_buf = NULLUsefulBuf;
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.install, suit_encode, &install_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        suit_encode->install = UsefulBuf_Const(install_buf);

        if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_IN_ENVELOPE) {
            suit_digest_t *install_digest = &suit_encode->install_digest;
            result = suit_generate_digest_include_header(suit_encode->install.ptr, suit_encode->install.len, suit_encode, install_digest);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
    }

    if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_EXISTS) {
        UsefulBuf text_buf = NULLUsefulBuf;
        result = suit_encode_text(&manifest->sev_man_mem.text, suit_encode, &text_buf);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        suit_encode->text = UsefulBuf_Const(text_buf);

        if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_ENVELOPE) {
            suit_digest_t *text_digest = &suit_encode->text_digest;
            result = suit_generate_digest_include_header(suit_encode->text.ptr, suit_encode->text.len, suit_encode, text_digest);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
    }

    if (manifest->sev_man_mem.coswid_status & SUIT_SEVERABLE_EXISTS) {
        suit_encode->coswid = (UsefulBufC){.ptr = manifest->sev_man_mem.coswid.ptr, .len = manifest->sev_man_mem.coswid.len};
        if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_ENVELOPE) {
            suit_digest_t *coswid_digest = &suit_encode->coswid_digest;
            result = suit_generate_digest_include_header(suit_encode->coswid.ptr, suit_encode->coswid.len, suit_encode, coswid_digest);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
    }

    /* Encode whole manifest */
    UsefulBuf suit_manifest = NULLUsefulBuf;
    result = suit_use_suit_encode_buf(suit_encode, 0, &suit_manifest);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBOREncodeContext context;
    QCBOREncode_Init(&context, suit_manifest);
    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddUInt64ToMapN(&context, SUIT_MANIFEST_VERSION, manifest->version);
    QCBOREncode_AddUInt64ToMapN(&context, SUIT_MANIFEST_SEQUENCE_NUMBER, manifest->sequence_number);
    QCBOREncode_AddBytesToMapN(&context, SUIT_COMMON, UsefulBuf_Const(suit_common));

    if (manifest->reference_uri.len > 0) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_REFERENCE_URI, (UsefulBufC){.ptr = manifest->reference_uri.ptr, .len = manifest->reference_uri.len});
    }

    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->dependency_resolution)) {
        if (suit_encode->dependency_resolution_digest.bytes.len > 0) {
            /* severed */
            QCBOREncode_AddUInt64(&context, SUIT_DEPENDENCY_RESOLUTION);
            result = suit_encode_append_digest(&suit_encode->dependency_resolution_digest, 0, &context);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        else {
            QCBOREncode_AddBytesToMapN(&context, SUIT_DEPENDENCY_RESOLUTION, suit_encode->dependency_resolution);
        }
    }

    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->payload_fetch)) {
        if (suit_encode->payload_fetch_digest.bytes.len > 0) {
            /* severed */
            QCBOREncode_AddUInt64(&context, SUIT_PAYLOAD_FETCH);
            result = suit_encode_append_digest(&suit_encode->payload_fetch_digest, 0, &context);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        else {
            QCBOREncode_AddBytesToMapN(&context, SUIT_PAYLOAD_FETCH, suit_encode->payload_fetch);
        }
    }

    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->install)) {
        if (suit_encode->install_digest.bytes.len > 0) {
            /* severed */
            QCBOREncode_AddUInt64(&context, SUIT_INSTALL);
            result = suit_encode_append_digest(&suit_encode->install_digest, 0, &context);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        else {
            QCBOREncode_AddBytesToMapN(&context, SUIT_INSTALL, suit_encode->install);
        }
    }

    if (!UsefulBuf_IsNULLOrEmpty(validate_buf)) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_VALIDATE, UsefulBuf_Const(validate_buf));
    }

    if (!UsefulBuf_IsNULLOrEmpty(load_buf)) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_LOAD, UsefulBuf_Const(load_buf));
    }

    if (!UsefulBuf_IsNULLOrEmpty(run_buf)) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_RUN, UsefulBuf_Const(run_buf));
    }

    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->text)) {
        if (suit_encode->text_digest.bytes.len > 0) {
            /* severed */
            QCBOREncode_AddUInt64(&context, SUIT_TEXT);
            result = suit_encode_append_digest(&suit_encode->text_digest, 0, &context);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        else {
            QCBOREncode_AddBytesToMapN(&context, SUIT_TEXT, suit_encode->text);
        }
    }

    if (!UsefulBuf_IsNULLOrEmptyC(suit_encode->coswid)) {
        if (suit_encode->coswid_digest.bytes.len > 0) {
            /* severed */
            QCBOREncode_AddUInt64(&context, SUIT_COSWID);
            result = suit_encode_append_digest(&suit_encode->coswid_digest, 0, &context);
            if (result != SUIT_SUCCESS) {
                return result;
            }
        }
        else {
            QCBOREncode_AddBytesToMapN(&context, SUIT_COSWID, suit_encode->coswid);
        }
    }

    QCBOREncode_CloseMap(&context);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBORError error = QCBOREncode_Finish(&context, &suit_encode->manifest);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    return suit_fix_suit_encode_buf(suit_encode, suit_encode->manifest.len);
}

/*
    Public function. See suit_manifest_data.h
 */
suit_err_t suit_encode_envelope(uint8_t mode, const suit_envelope_t *envelope, const suit_mechanism_t *mechanism, uint8_t **buf, size_t *len) {
    suit_err_t result = SUIT_SUCCESS;
    suit_encode_t suit_encode = {
        .buf = *buf,
        .max_pos = *len
    };

    result = suit_encode_manifest(envelope, &suit_encode);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* calculate digest and signatures of suit-manifest */
    UsefulBuf digest;
    result = suit_generate_encoded_digest(suit_encode.manifest.ptr, suit_encode.manifest.len, &suit_encode, &digest);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    UsefulBuf signatures[SUIT_MAX_ARRAY_LENGTH] = {0};
    size_t num_signatures;
    for (num_signatures = 0; num_signatures < SUIT_MAX_KEY_NUM; num_signatures++) {
        switch (mechanism->keys[num_signatures].cose_algorithm_id) {
        case T_COSE_ALGORITHM_ES256:
            result = SUIT_SUCCESS;
            break;
        default:
            result = SUIT_ERR_ABORT;
        }
        if (result == SUIT_SUCCESS) {
        }
        else if (result == SUIT_ERR_ABORT) {
            break;
        }
        else {
            return result;
        }

        result = suit_use_suit_encode_buf(&suit_encode, 0, &signatures[num_signatures]);
        if (result != SUIT_SUCCESS) {
            return result;
        }

        switch (mechanism->cose_tag) {
        case CBOR_TAG_COSE_SIGN1:
            result = suit_sign_cose_sign1(UsefulBuf_Const(digest), &mechanism->keys[num_signatures], &signatures[num_signatures]);
            break;
        case CBOR_TAG_SIGN:
        case CBOR_TAG_MAC:
        case CBOR_TAG_COSE_MAC0:
        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (!suit_continue(mode, result)) {
            return result;
        }

        result = suit_fix_suit_encode_buf(&suit_encode, signatures[num_signatures].len);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }

    UsefulBuf suit_envelope = NULLUsefulBuf;
    result = suit_use_suit_encode_buf(&suit_encode, 0, &suit_envelope);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, suit_envelope);
    QCBOREncode_AddTag(&context, SUIT_ENVELOPE_CBOR_TAG);
    QCBOREncode_OpenMap(&context);
    /* TODO
    result = suit_encode_append_delegation(&envelope->delegation, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }
    */

    result = suit_encode_append_authentication_wrapper(mode, UsefulBuf_Const(digest), signatures, num_signatures, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }

    result = suit_encode_append_payloads(mode, envelope, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }

    result = suit_encode_append_manifest(&suit_encode, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }

    result = suit_encode_append_severed_members(&suit_encode, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }

out:
    QCBOREncode_CloseMap(&context);
    UsefulBufC tmp;
    QCBORError error = QCBOREncode_Finish(&context, &tmp);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    if (result != SUIT_SUCCESS) {
        return result;
    }
    result = suit_fix_suit_encode_buf(&suit_encode, tmp.len);
    if (result == SUIT_SUCCESS) {
        *buf = (uint8_t *)tmp.ptr;
        *len = tmp.len;
    }
    return result;
}

