/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_common.h"
#include "suit_common.h"
#include "suit_manifest_data.h"
#include "suit_cose.h"
#include "suit_digest.h"
#define SUIT_ENCODE_MAX_BUFFER_SIZE 2048

suit_err_t suit_encode_append_severable_manifest_members(const suit_encode_t *suit_encode, QCBOREncodeContext *context) {
    if (suit_encode->dependency_resolution.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_DEPENDENCY_RESOLUTION, suit_encode->dependency_resolution);
    }
    if (suit_encode->payload_fetch.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_PAYLOAD_FETCH, suit_encode->payload_fetch);
    }
    if (suit_encode->install.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_INSTALL, suit_encode->install);
    }
    if (suit_encode->text.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_TEXT, suit_encode->text);
    }
    if (suit_encode->coswid.len > 0) {
        QCBOREncode_AddBytesToMapN(context, SUIT_COSWID, suit_encode->coswid);
    }
    return SUIT_SUCCESS;
}
suit_err_t suit_encode_append_manifest(const suit_encode_t *suit_encode, QCBOREncodeContext *context) {
    QCBOREncode_AddBytesToMapN(context, SUIT_MANIFEST, suit_encode->manifest);
    return SUIT_SUCCESS;
}
suit_err_t suit_encode_append_digest(const suit_digest_t *digest, QCBOREncodeContext *context) {
    QCBOREncode_OpenArray(context);
    QCBOREncode_AddUInt64(context, digest->algorithm_id);
    QCBOREncode_AddBytes(context, (UsefulBufC){.ptr = digest->bytes.ptr, .len = digest->bytes.len});
    QCBOREncode_CloseArray(context);
    return SUIT_SUCCESS;
}
suit_err_t suit_encode_digest(const suit_digest_t *digest, UsefulBuf *buf) {
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, *buf);
    suit_encode_append_digest(digest, &context);
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return SUIT_SUCCESS;
}

suit_err_t suit_generate_digest(const uint8_t *ptr, const size_t len, suit_digest_t *digest, uint8_t *hash, size_t hash_len) {
    if (hash_len != SHA256_DIGEST_LENGTH) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = suit_generate_sha256(ptr, len, hash, hash_len);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    digest->algorithm_id = SUIT_ALGORITHM_ID_SHA256;
    digest->bytes.ptr = hash;
    digest->bytes.len = SHA256_DIGEST_LENGTH;
    return SUIT_SUCCESS;
}

suit_err_t suit_generate_digest_include_header(const uint8_t *ptr, const size_t len, suit_digest_t *digest, uint8_t *hash, size_t hash_len) {
    UsefulBuf_MAKE_STACK_UB(tmp_buf, SUIT_ENCODE_MAX_BUFFER_SIZE);
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, tmp_buf);
    QCBOREncode_AddBytes(&context, (UsefulBufC){.ptr = ptr, .len = len});
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    return suit_generate_digest(t_buf.ptr, t_buf.len, digest, hash, hash_len);
}
suit_err_t suit_generate_encoded_digest(const uint8_t *ptr, const size_t len, UsefulBuf *buf) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    suit_digest_t digest;
    suit_err_t result = suit_generate_digest_include_header(ptr, len, &digest, hash, sizeof(hash));
    if (result != SUIT_SUCCESS) {
        return result;
    }
    result = suit_encode_digest(&digest, buf);
    return result;
}

suit_err_t suit_encode_append_authentication_wrapper(const UsefulBufC *manifest, const struct t_cose_key signing_key, QCBOREncodeContext *context)
{
    suit_err_t result;
    UsefulBuf_MAKE_STACK_UB(digest, SUIT_ENCODE_MAX_BUFFER_SIZE);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_sign1_sign_ctx   sign_ctx;

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);

    result = suit_generate_encoded_digest(manifest->ptr, manifest->len, &digest);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    UsefulBufC c_digest = (UsefulBufC){.ptr = digest.ptr, .len = digest.len};

    QCBOREncodeContext t_context;
    UsefulBuf_MAKE_STACK_UB(tmp_buf, SUIT_ENCODE_MAX_BUFFER_SIZE);
    QCBOREncode_Init(&t_context, tmp_buf);
    QCBOREncode_OpenArray(&t_context);
    QCBOREncode_AddBytes(&t_context, c_digest);

    UsefulBuf_MAKE_STACK_UB(signature, SUIT_ENCODE_MAX_BUFFER_SIZE);

    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign(&sign_ctx,
                        c_digest,
                        signature,
                        &signed_cose);

    QCBOREncode_AddBytes(&t_context, (UsefulBufC){.ptr = signed_cose.ptr, .len = signed_cose.len});

    QCBOREncode_CloseArray(&t_context);

    UsefulBufC buf;

    QCBORError error = QCBOREncode_Finish(&t_context, &buf);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }

    QCBOREncode_AddBytesToMapN(context, SUIT_AUTHENTICATION, buf);
    return result;
}

suit_err_t suit_append_directive_override_parameters(const suit_parameters_list_t *params_list, QCBOREncodeContext *context) {
    uint8_t tmp_buf[SUIT_ENCODE_MAX_BUFFER_SIZE];
    UsefulBuf t_buf;

    QCBOREncode_OpenMap(context);
    suit_err_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        const suit_parameters_t *item = &params_list->params[i];
        switch (item->label) {
            case SUIT_PARAMETER_COMPONENT_OFFSET:
            case SUIT_PARAMETER_IMAGE_SIZE:
            case SUIT_PARAMETER_COMPRESSION_INFO:
            case SUIT_PARAMETER_SOURCE_COMPONENT:
                QCBOREncode_AddUInt64ToMapN(context, item->label, item->value.uint64);
                break;
            case SUIT_PARAMETER_URI:
                QCBOREncode_AddTextToMapN(context, item->label, (UsefulBufC){.ptr = item->value.string.ptr, .len = item->value.string.len});
                break;
            case SUIT_PARAMETER_VENDOR_IDENTIFIER:
            case SUIT_PARAMETER_CLASS_IDENTIFIER:
                QCBOREncode_AddBytesToMapN(context, item->label, (UsefulBufC){.ptr = item->value.string.ptr, .len = item->value.string.len});
                break;
            case SUIT_PARAMETER_IMAGE_DIGEST:
                t_buf = (UsefulBuf){.ptr = tmp_buf, .len = SUIT_ENCODE_MAX_BUFFER_SIZE};
                result = suit_encode_digest(&item->value.digest, &t_buf);
                QCBOREncode_AddBytesToMapN(context, item->label, (UsefulBufC){.ptr = t_buf.ptr, .len = t_buf.len});
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

suit_err_t suit_encode_common_sequence(suit_command_sequence_t *cmd_seq, UsefulBuf *buf) {
    suit_err_t result = SUIT_SUCCESS;
    UsefulBuf_MAKE_STACK_UB(tmp_buf, SUIT_ENCODE_MAX_BUFFER_SIZE);
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
            case SUIT_CONDITION_COMPONENT_OFFSET:
            case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            case SUIT_DIRECTIVE_SET_DEPENDENCY_INDEX:
            case SUIT_DIRECTIVE_FETCH:
            case SUIT_DIRECTIVE_COPY:
            case SUIT_DIRECTIVE_RUN:
                QCBOREncode_AddUInt64(&context, item->label);
                QCBOREncode_AddUInt64(&context, item->value.uint64);
                break;
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                QCBOREncode_AddUInt64(&context, item->label);
                result = suit_append_directive_override_parameters(&item->value.params_list, &context);
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
            case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
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
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return result;
}
suit_err_t suit_encode_common_sequence_bstr(const suit_command_sequence_t *cmd_seq, UsefulBuf *buf) {
    UsefulBuf_MAKE_STACK_UB(tmp_buf, SUIT_ENCODE_MAX_BUFFER_SIZE);
    suit_err_t result = suit_encode_common_sequence((suit_command_sequence_t *)cmd_seq, &tmp_buf);
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
    return result;
}

suit_err_t suit_encode_common(const suit_common_t *suit_common, UsefulBuf *buf) {
    UsefulBuf_MAKE_STACK_UB(suit_common_sequence, SUIT_ENCODE_MAX_BUFFER_SIZE);
    suit_err_t result = suit_encode_common_sequence((suit_command_sequence_t *)&suit_common->cmd_seq, &suit_common_sequence);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBOREncodeContext context;
    QCBOREncode_Init(&context, *buf);
    QCBOREncode_OpenMap(&context);

    // suit-components
    QCBOREncode_OpenArrayInMapN(&context, SUIT_COMPONENTS);
    for (size_t i = 0; i < suit_common->components.len; i++) {
        const suit_component_identifier_t *component_id = &suit_common->components.comp_id[i];
        QCBOREncode_OpenArray(&context);
        for (size_t j = 0; j < component_id->len; j++) {
            const suit_buf_t *identifier = &component_id->identifier[j];
            QCBOREncode_AddBytes(&context, (UsefulBufC){.ptr = identifier->ptr, .len = identifier->len});
        }
        QCBOREncode_CloseArray(&context);
    }
    QCBOREncode_CloseArray(&context);

    // suit-common-sequence
    if (suit_common_sequence.len > 2) {
        UsefulBufC t_buf = (UsefulBufC){.ptr = suit_common_sequence.ptr, .len = suit_common_sequence.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_COMMON_SEQUENCE, t_buf);
    }

    QCBOREncode_CloseMap(&context);
    UsefulBufC t_buf;
    QCBORError error = QCBOREncode_Finish(&context, &t_buf);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    *buf = (UsefulBuf){.ptr = (void *)t_buf.ptr, .len = t_buf.len};
    return result;
}
suit_err_t suit_encode_text(const suit_text_t *text, UsefulBuf *buf) {
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, *buf);

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
    return SUIT_SUCCESS;
}
suit_err_t suit_encode_text_bstr(const suit_text_t *text, UsefulBuf *buf) {
    UsefulBuf_MAKE_STACK_UB(tmp_buf, SUIT_ENCODE_MAX_BUFFER_SIZE);
    suit_err_t result = suit_encode_text(text, &tmp_buf);
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
    return result;
}
suit_err_t suit_encode_manifest(const suit_envelope_t *envelope, suit_encode_t *suit_encode) {
    const suit_manifest_t *manifest = &envelope->manifest;
    UsefulBuf_MAKE_STACK_UB(suit_common, SUIT_ENCODE_MAX_BUFFER_SIZE);
    suit_err_t result = suit_encode_common(&manifest->common, &suit_common);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBOREncodeContext context;
    QCBOREncode_Init(&context, (UsefulBuf){.ptr = &suit_encode->buf[suit_encode->pos], .len = suit_encode->max_pos - suit_encode->pos});
    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddUInt64ToMapN(&context, SUIT_MANIFEST_VERSION, manifest->version);
    QCBOREncode_AddUInt64ToMapN(&context, SUIT_MANIFEST_SEQUENCE_NUMBER, manifest->sequence_number);
    QCBOREncode_AddBytesToMapN(&context, SUIT_COMMON, (UsefulBufC){.ptr = suit_common.ptr, .len = suit_common.len});

    UsefulBuf buf;
    uint8_t hash[SHA256_DIGEST_WORK_SPACE_LENGTH];
    uint8_t tmp_buf[SUIT_ENCODE_MAX_BUFFER_SIZE];
    UsefulBufC t_buf;
    suit_digest_t digest;

    if (manifest->reference_uri.len > 0) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_REFERENCE_URI, (UsefulBufC){.ptr = manifest->reference_uri.ptr, .len = manifest->reference_uri.len});
    }

    if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_MANIFEST) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.dependency_resolution, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_DEPENDENCY_RESOLUTION, t_buf);
    }
    else if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        const UsefulBufC *dependency_resolution_buf = &suit_encode->dependency_resolution;
        if (dependency_resolution_buf->len == 0) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_generate_digest_include_header(dependency_resolution_buf->ptr, dependency_resolution_buf->len, &digest, hash, sizeof(hash) );
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        QCBOREncode_AddUInt64(&context, SUIT_DEPENDENCY_RESOLUTION);
        result = suit_encode_append_digest(&digest, &context);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
    }

    if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_MANIFEST) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.payload_fetch, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_PAYLOAD_FETCH, t_buf);
    }
    else if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        const UsefulBufC *payload_fetch_buf = &suit_encode->payload_fetch;
        if (payload_fetch_buf->len == 0) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_generate_digest_include_header(payload_fetch_buf->ptr, payload_fetch_buf->len, &digest, hash, sizeof(hash));
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        QCBOREncode_AddUInt64(&context, SUIT_PAYLOAD_FETCH);
        result = suit_encode_append_digest(&digest, &context);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
    }

    if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_IN_MANIFEST) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.install, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_INSTALL, t_buf);
    }
    else if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        const UsefulBufC *install_buf = &suit_encode->install;
        if (install_buf->len == 0) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_generate_digest_include_header(install_buf->ptr, install_buf->len, &digest, hash, sizeof(hash));
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        QCBOREncode_AddUInt64(&context, SUIT_INSTALL);
        result = suit_encode_append_digest(&digest, &context);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
    }

    if (manifest->unsev_mem.validate.len > 0) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->unsev_mem.validate, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_VALIDATE, t_buf);
    }

    if (manifest->unsev_mem.load.len > 0) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->unsev_mem.load, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_LOAD, t_buf);
    }

    if (manifest->unsev_mem.run.len > 0) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->unsev_mem.run, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_RUN, t_buf);
    }

    if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_MANIFEST) {
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_text(&manifest->sev_man_mem.text, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        t_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
        QCBOREncode_AddBytesToMapN(&context, SUIT_TEXT, t_buf);
    }
    else if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        const UsefulBufC *text_buf = &suit_encode->text;
        if (text_buf->len == 0) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_generate_digest(text_buf->ptr, text_buf->len, &digest, hash, sizeof(hash));
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        QCBOREncode_AddUInt64(&context, SUIT_TEXT);
        result = suit_encode_append_digest(&digest, &context);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
    }

    if (manifest->sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_MANIFEST) {
        QCBOREncode_AddBytesToMapN(&context, SUIT_COSWID, (UsefulBufC){.ptr = manifest->sev_man_mem.coswid.ptr, .len = manifest->sev_man_mem.coswid.len});
    }
    else if (manifest->sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        const UsefulBufC *payload_fetch_buf = &suit_encode->payload_fetch;
        if (payload_fetch_buf->len == 0) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
        buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_generate_digest_include_header(payload_fetch_buf->ptr, payload_fetch_buf->len, &digest, hash, sizeof(hash));
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        QCBOREncode_AddUInt64(&context, SUIT_COSWID);
        result = suit_encode_append_digest(&digest, &context);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
    }

out:
    QCBOREncode_CloseMap(&context);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBORError error = QCBOREncode_Finish(&context, &suit_encode->manifest);
    if (error != QCBOR_SUCCESS) {
        return suit_error_from_qcbor_error(error);
    }
    return SUIT_SUCCESS;
}
suit_err_t suit_encode_severable_manifest_members_in_envelope(const suit_envelope_t *envelope, suit_encode_t *suit_encode) {
    suit_err_t result = SUIT_SUCCESS;
    const suit_manifest_t *manifest = &envelope->manifest;

    UsefulBuf buf;
    if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        UsefulBufC *dependency_resolution_buf = &suit_encode->dependency_resolution;
        buf = (UsefulBuf){.ptr = &suit_encode->buf[suit_encode->pos], .len = suit_encode->max_pos - suit_encode->pos};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.dependency_resolution, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        suit_encode->pos += buf.len;
        *dependency_resolution_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
    }
    if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        UsefulBufC *payload_fetch_buf = &suit_encode->payload_fetch;
        buf = (UsefulBuf){.ptr = &suit_encode->buf[suit_encode->pos], .len = suit_encode->max_pos - suit_encode->pos};

        //buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.payload_fetch, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        suit_encode->pos += buf.len;
        *payload_fetch_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
    }
    if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        UsefulBufC *install_buf = &suit_encode->install;
        //buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        buf = (UsefulBuf){.ptr = &suit_encode->buf[suit_encode->pos], .len = suit_encode->max_pos - suit_encode->pos};

        result = suit_encode_common_sequence((suit_command_sequence_t *)&manifest->sev_man_mem.install, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        suit_encode->pos += buf.len;
        *install_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
    }
    if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        UsefulBufC *text_buf = &suit_encode->text;
        //buf = (UsefulBuf){.ptr = tmp_buf, .len = sizeof(tmp_buf)};
        buf = (UsefulBuf){.ptr = &suit_encode->buf[suit_encode->pos], .len = suit_encode->max_pos - suit_encode->pos};
        result = suit_encode_text(&manifest->sev_man_mem.text, &buf);
        if (result != SUIT_SUCCESS) {
            goto out;
        }
        suit_encode->pos += buf.len;
        *text_buf = (UsefulBufC){.ptr = buf.ptr, .len = buf.len};
    }
    if (manifest->sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        suit_encode->coswid = (UsefulBufC){.ptr = manifest->sev_man_mem.coswid.ptr, .len = manifest->sev_man_mem.coswid.len};
    }

out:
    return result;
}

suit_err_t suit_encode_envelope(const suit_envelope_t *envelope, t_cose_key *signing_key, uint8_t *buf, size_t *len) {
    suit_err_t result;
    UsefulBuf_MAKE_STACK_UB(tmp_buf, SUIT_ENCODE_MAX_BUFFER_SIZE);
    suit_encode_t suit_encode = {
        .pos = 0,
        .max_pos = tmp_buf.len,
        .buf = tmp_buf.ptr
    };

    result = suit_encode_severable_manifest_members_in_envelope(envelope, &suit_encode);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    result = suit_encode_manifest(envelope, &suit_encode);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    QCBOREncodeContext context;
    QCBOREncode_Init(&context, (UsefulBuf){buf, *len});
    QCBOREncode_OpenMap(&context);
    /* TODO
    result = suit_encode_append_delegation(&envelope->delegation, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }
    */

    result = suit_encode_append_authentication_wrapper(&suit_encode.manifest, *signing_key, &context);

    if (result != SUIT_SUCCESS) {
        goto out;
    }
    result = suit_encode_append_manifest(&suit_encode, &context);
    if (result != SUIT_SUCCESS) {
        goto out;
    }
    result = suit_encode_append_severable_manifest_members(&suit_encode, &context);
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
    *len = tmp.len;
    return SUIT_SUCCESS;
}

