/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_DATA_H
#define SUIT_MANIFEST_DATA_H

#include "suit_common.h"
#include "suit_cose.h"

/*!
    \file   suit_manifest_data.h

    \brief  Declarations of structures and functions
 */
suit_err_t suit_use_suit_encode_buf(suit_encode_t *suit_encode, size_t len, UsefulBuf *buf);
suit_err_t suit_fix_suit_encode_buf(suit_encode_t *suit_encode, const size_t used_len);
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
suit_err_t suit_decode_envelope(uint8_t mode, suit_buf_t *buf, suit_envelope_t *envelope, const suit_key_t *public_key);

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

suit_err_t suit_decode_dependencies_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_dependencies_t *dependencies);
suit_err_t suit_decode_components_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_components_t *components);
suit_err_t suit_decode_digest_from_item(uint8_t mode, QCBORDecodeContext *context, QCBORItem *item, bool next, suit_digest_t *digest);

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
suit_err_t suit_encode_envelope(uint8_t mode, const suit_envelope_t *envelope, const suit_key_t *signing_key, uint8_t *buf, size_t *len);

#endif  // SUIT_MANIFEST_DATA_H
