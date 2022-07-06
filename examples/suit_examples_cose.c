#include "suit_examples_common.h"

#if defined(LIBCSUIT_PSA_CRYPTO_C)
suit_err_t suit_create_es_key(const int nid, const int hash, const bool is_private, const unsigned char *key, const size_t key_len, suit_key_t *cose_public_key) {
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

suit_err_t suit_key_init_es256_key_pair(const unsigned char *private_key, const unsigned char *public_key, suit_key_t *cose_key_pair) {
    return suit_create_es_key(PSA_ECC_FAMILY_SECP_R1, PSA_ALG_SHA_256, true, private_key, PRIME256V1_PRIVATE_KEY_CHAR_LENGTH, cose_key_pair);
}

suit_err_t suit_key_init_es256_public_key(const unsigned char *public_key, suit_key_t *cose_public_key) {
    return suit_create_es_key(PSA_ECC_FAMILY_SECP_R1, PSA_ALG_SHA_256, false, public_key, PRIME256V1_PUBLIC_KEY_CHAR_LENGTH, cose_public_key);
}

suit_err_t suit_free_key(suit_key_t *key) {
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
suit_err_t suit_create_openssl_es_key(suit_key_t *key) {
    suit_err_t      result = SUIT_SUCCESS;
    EVP_PKEY        *pkey = NULL;
    EVP_PKEY_CTX    *ctx = NULL;
    OSSL_PARAM_BLD  *param_bld = NULL;
    OSSL_PARAM      *params = NULL;
    BIGNUM *priv;

    const char *group_name =    (key->cose_algorithm_id == T_COSE_ALGORITHM_ES256) ? "prime256v1" :
                                (key->cose_algorithm_id == T_COSE_ALGORITHM_ES384) ? "secp384r1" :
                                (key->cose_algorithm_id == T_COSE_ALGORITHM_ES512) ? "secp521r1" :
                                                                                          NULL;
    if (group_name == NULL) {
        return SUIT_ERR_INVALID_VALUE;
    }


    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", group_name, 0)
        || !OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", key->public_key, key->public_key_len)) {
        result = SUIT_ERR_FATAL;
        goto out;
    }
    if (key->private_key != NULL) {
        priv = BN_bin2bn(key->private_key, key->private_key_len, NULL);
        if (priv == NULL) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
        if (!OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv)) {
            result = SUIT_ERR_FATAL;
            goto out;
        }
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);

    if (params == NULL) {
        result = SUIT_ERR_FATAL;
        goto out;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        result = SUIT_ERR_FATAL;
        goto out;
    }
    if (ctx == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        result = SUIT_ERR_FATAL;
        goto out;
    }

    key->cose_key.k.key_ptr  = pkey;
    key->cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;

out:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    BN_free(priv);
    OSSL_PARAM_BLD_free(param_bld);
    return result;
}

suit_err_t suit_key_init_es256_key_pair(const unsigned char *private_key, const unsigned char *public_key, suit_key_t *cose_key_pair) {
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = PRIME256V1_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = PRIME256V1_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    return suit_create_openssl_es_key(cose_key_pair);
}

suit_err_t suit_key_init_es384_key_pair(const unsigned char *private_key, const unsigned char *public_key, suit_key_t *cose_key_pair) {
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = SECP384R1_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = SECP384R1_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_ES384;
    return suit_create_openssl_es_key(cose_key_pair);
}

suit_err_t suit_key_init_es521_key_pair(const unsigned char *private_key, const unsigned char *public_key, suit_key_t *cose_key_pair) {
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = SECP521R1_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = SECP521R1_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_ES512;
    return suit_create_openssl_es_key(cose_key_pair);
}

suit_err_t suit_key_init_es256_public_key(const unsigned char *public_key, suit_key_t *cose_public_key) {
    cose_public_key->private_key = NULL;
    cose_public_key->private_key_len = 0;
    cose_public_key->public_key = public_key;
    cose_public_key->public_key_len = PRIME256V1_PUBLIC_KEY_LENGTH;
    cose_public_key->cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    return suit_create_openssl_es_key(cose_public_key);
}

suit_err_t suit_key_init_es384_public_key(const unsigned char *public_key, suit_key_t *cose_public_key) {
    cose_public_key->private_key = NULL;
    cose_public_key->private_key_len = 0;
    cose_public_key->public_key = public_key;
    cose_public_key->public_key_len = SECP384R1_PUBLIC_KEY_LENGTH;
    cose_public_key->cose_algorithm_id = T_COSE_ALGORITHM_ES384;
    return suit_create_openssl_es_key(cose_public_key);
}

suit_err_t suit_key_init_es521_public_key(const unsigned char *public_key, suit_key_t *cose_public_key) {
    cose_public_key->private_key = NULL;
    cose_public_key->private_key_len = 0;
    cose_public_key->public_key = public_key;
    cose_public_key->public_key_len = SECP521R1_PUBLIC_KEY_LENGTH;
    cose_public_key->cose_algorithm_id = T_COSE_ALGORITHM_ES512;
    return suit_create_openssl_es_key(cose_public_key);
}

suit_err_t suit_free_key(const suit_key_t *key) {
    EVP_PKEY_free(key->cose_key.k.key_ptr);
    return SUIT_SUCCESS;
}

#endif /* LIBCSUIT_PSA_CRYPTO_C */

