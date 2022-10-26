/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef SUIT_EXAMPLES_COMMON_H
#define SUIT_EXAMPLES_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <csuit/suit_cose.h>

#define PRIME256V1_PUBLIC_KEY_DER_SIZE      91
#define PRIME256V1_PUBLIC_KEY_CHAR_SIZE     130
#define PRIME256V1_PRIVATE_KEY_DER_SIZE     121
#define PRIME256V1_PRIVATE_KEY_CHAR_SIZE    64

#define PRIME256V1_PRIVATE_KEY_START_INDEX  7
#define PRIME256V1_PUBLIC_KEY_IN_KEY_PAIR_START_INDEX  56
#define PRIME256V1_PUBLIC_KEY_START_INDEX   26

#define PRIME256V1_PRIVATE_KEY_LENGTH       32
#define PRIME256V1_PRIVATE_KEY_CHAR_LENGTH  64
#define PRIME256V1_PUBLIC_KEY_LENGTH        65
#define PRIME256V1_PUBLIC_KEY_CHAR_LENGTH   130
#define SECP384R1_PRIVATE_KEY_LENGTH        48
#define SECP384R1_PRIVATE_KEY_CHAR_LENGTH   96
#define SECP384R1_PUBLIC_KEY_LENGTH         97
#define SECP384R1_PUBLIC_KEY_CHAR_LENGTH    194
#define SECP521R1_PRIVATE_KEY_LENGTH        66
#define SECP521R1_PRIVATE_KEY_CHAR_LENGTH   132
#define SECP521R1_PUBLIC_KEY_LENGTH         133
#define SECP521R1_PUBLIC_KEY_CHAR_LENGTH    266

size_t read_from_file(const char *file_path, const size_t buf_len, uint8_t *buf);
size_t write_to_file(const char *file_path, const size_t buf_len, const void *buf);

/*!
    \brief  Create ES256 public key

    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer of suit_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FATAL.

    The length of the char array public key is estimated from the algorithm and library.
 */

suit_err_t suit_key_init_es256_key_pair(const unsigned char *private_key, const unsigned char *public_key, suit_key_t *cose_key_pair);

/*!
    \brief  Create ES256 key pair

    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer of suit_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
suit_err_t suit_key_init_es256_public_key(const unsigned char *public_key, suit_key_t *cose_key_pair);

suit_err_t suit_free_key(const suit_key_t *key);
#endif  /* SUIT_EXAMPLES_COMMON_H */
