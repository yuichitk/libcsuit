#include "suit_examples_common.h"

bool suit_key_size_is_valid(const char *key, const size_t len) {
    return (strnlen(key, len) == len) && (key[len] == '\0');
}

#if defined(LIBCSUIT_PSA_CRYPTO_C)
suit_err_t suit_create_es_key(const int nid, const int hash, const bool is_private, const char *key, const size_t key_len, struct t_cose_key *cose_public_key) {
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t     key_handle = 0;
    psa_status_t         result;

    result = psa_crypto_init();

    if (result != PSA_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    psa_key_usage_t usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT;
    if (is_private) {
        usage |= PSA_KEY_USAGE_SIGN_HASH;
    }
    psa_set_key_usage_flags(&key_attributes, usage);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(hash));
    if (is_private) {
        psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(nid));
    }
    else {
        psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(nid));
    }

    result = psa_import_key(&key_attributes,
                            (const unsigned char*)key,
                            key_len,
                            &key_handle);

    if (result != PSA_SUCCESS) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    cose_public_key->k.key_handle = key_handle;
    cose_public_key->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return SUIT_SUCCESS;
}

suit_err_t suit_create_es256_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    if (!suit_key_size_is_valid(private_key, PRIME256V1_PRIVATE_KEY_CHAR_LENGTH)) {
        return SUIT_ERR_FATAL;
    }
    return suit_create_es_key(PSA_ECC_FAMILY_SECP_R1, PSA_ALG_SHA_256, true, private_key, PRIME256V1_PRIVATE_KEY_CHAR_LENGTH, cose_key_pair);
}

suit_err_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    if (!suit_key_size_is_valid(public_key, PRIME256V1_PUBLIC_KEY_CHAR_LENGTH)) {
        return SUIT_ERR_FATAL;
    }
    return suit_create_es_key(PSA_ECC_FAMILY_SECP_R1, PSA_ALG_SHA_256, false, public_key, PRIME256V1_PUBLIC_KEY_CHAR_LENGTH, cose_public_key);
}

suit_err_t suit_free_key(struct t_cose_key *key) {
    psa_destroy_key(key->k.key_handle );
    return SUIT_SUCCESS;
}
#else /* LIBCSUIT_PSA_CRYPTO_C */
/*
    \brief      Internal function calls OpenSSL functions to create public key.

    \param[in]  nid                 EC network id.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer and length of the resulting key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */
suit_err_t suit_create_openssl_es_key(int nid, const char *private_key, const char *public_key, struct t_cose_key *cose_key) {
    EC_GROUP    *ec_group = NULL;
    EC_KEY      *ec_key = NULL;
    BIGNUM      *private_key_bn = NULL;
    EC_POINT    *pub_key_point = NULL;
    int         result = 0;

    ec_group = EC_GROUP_new_by_curve_name(nid);
    if (ec_group == NULL) {
        return SUIT_ERR_FATAL;
    }
    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        return SUIT_ERR_FATAL;
    }
    result = EC_KEY_set_group(ec_key, ec_group);
    if (!result) {
        return SUIT_ERR_FATAL;
    }

    if (private_key != NULL) {
        private_key_bn = BN_new();
        if (private_key_bn == NULL) {
            return SUIT_ERR_FATAL;
        }
        BN_zero(private_key_bn);
        result = BN_hex2bn(&private_key_bn, private_key);
        if(private_key_bn == 0) {
            return SUIT_ERR_FATAL;
        }
        result = EC_KEY_set_private_key(ec_key, private_key_bn);
        if (!result) {
            return SUIT_ERR_FATAL;
        }
    }

    pub_key_point = EC_POINT_new(ec_group);
    if (pub_key_point == NULL) {
        return SUIT_ERR_FATAL;
    }
    pub_key_point = EC_POINT_hex2point(ec_group, public_key, pub_key_point, NULL);
    if (pub_key_point == NULL) {
        return SUIT_ERR_FATAL;
    }
    result = EC_KEY_set_public_key(ec_key, pub_key_point);
    if (result == 0) {
        return SUIT_ERR_FATAL;
    }

    cose_key->k.key_ptr  = ec_key;
    cose_key->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;
}

suit_err_t suit_create_es256_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    if (!suit_key_size_is_valid(private_key, PRIME256V1_PRIVATE_KEY_CHAR_LENGTH) ||
        !suit_key_size_is_valid(public_key, PRIME256V1_PUBLIC_KEY_CHAR_LENGTH)) {
        return SUIT_ERR_FATAL;
    }
    return suit_create_openssl_es_key(NID_X9_62_prime256v1, private_key, public_key, cose_key_pair);
}

suit_err_t suit_create_es384_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    if (!suit_key_size_is_valid(private_key, SECP384R1_PRIVATE_KEY_CHAR_LENGTH) ||
        !suit_key_size_is_valid(public_key, SECP384R1_PUBLIC_KEY_CHAR_LENGTH)) {
        return SUIT_ERR_FATAL;
    }
    return suit_create_openssl_es_key(NID_secp384r1, private_key, public_key, cose_key_pair);
}

suit_err_t suit_create_es521_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    if (!suit_key_size_is_valid(private_key, SECP521R1_PRIVATE_KEY_CHAR_LENGTH) ||
        !suit_key_size_is_valid(public_key, SECP521R1_PUBLIC_KEY_CHAR_LENGTH)) {
        return SUIT_ERR_FATAL;
    }
    return suit_create_openssl_es_key(NID_secp521r1, private_key, public_key, cose_key_pair);
}

/*
    \brief      Internal function calls OpenSSL functions to create public key.

    \param[in]  nid                 EC network id.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[out] cose_public_key     Pointer and length of the resulting key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.
 */
suit_err_t suit_create_openssl_es_public_key(int nid, const char *public_key, struct t_cose_key *cose_public_key) {
    EC_GROUP    *ec_group = NULL;
    EC_KEY      *ec_key = NULL;
    EC_POINT    *ec_point = NULL;
    int         result = 0;

    ec_group = EC_GROUP_new_by_curve_name(nid);
    if (ec_group == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    result = EC_KEY_set_group(ec_key, ec_group);
    if (!result) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    ec_point = EC_POINT_hex2point(ec_group, public_key, ec_point, NULL);
    if (ec_point == NULL) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }
    result = EC_KEY_set_public_key(ec_key, ec_point);
    if (result == 0) {
        return SUIT_ERR_FAILED_TO_VERIFY;
    }

    cose_public_key->k.key_ptr  = ec_key;
    cose_public_key->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;
}

suit_err_t suit_create_es256_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    //return suit_create_openssl_es_public_key(NID_X9_62_prime256v1, public_key, cose_public_key);
    return suit_create_openssl_es_key(NID_X9_62_prime256v1, NULL, public_key, cose_public_key);
}

suit_err_t suit_create_es384_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_openssl_es_key(NID_secp384r1, NULL, public_key, cose_public_key);
}

suit_err_t suit_create_es521_public_key(const char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_openssl_es_key(NID_secp521r1, NULL, public_key, cose_public_key);
}

suit_err_t suit_free_key(struct t_cose_key *key) {
    EC_KEY_free(key->k.key_ptr);
    return SUIT_SUCCESS;
}

#endif /* LIBCSUIT_PSA_CRYPTO_C */

