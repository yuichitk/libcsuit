#include "suit_examples_common.h"

#if defined(LIBCSUIT_PSA_CRYPTO_C)
suit_err_t suit_create_es_key(const int nid, const int hash, const bool is_private, const unsigned char *key, const size_t key_len, struct t_cose_key *cose_public_key) {
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

suit_err_t suit_create_es256_key_pair(const unsigned char *private_key, const unsigned char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_es_key(PSA_ECC_FAMILY_SECP_R1, PSA_ALG_SHA_256, true, private_key, PRIME256V1_PRIVATE_KEY_CHAR_LENGTH, cose_key_pair);
}

suit_err_t suit_create_es256_public_key(const unsigned char *public_key, struct t_cose_key *cose_public_key) {
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
suit_err_t suit_create_openssl_es_key(int nid, const unsigned char *private_key, const unsigned char *public_key, struct t_cose_key *cose_key) {
    suit_err_t      result = SUIT_SUCCESS;
    EVP_PKEY        *pkey = NULL;
    EVP_PKEY_CTX    *ctx;
    BIGNUM *priv;
    OSSL_PARAM_BLD  *param_bld;
    OSSL_PARAM      *params = NULL;

    priv = BN_bin2bn(private_key, 32, NULL);

    param_bld = OSSL_PARAM_BLD_new();
    if (priv != NULL && param_bld != NULL
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", "prime256v1", 0)
        && OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", public_key, 65)) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    }

    if (params == NULL) {
        result = SUIT_ERR_FATAL;
        goto out;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        result = SUIT_ERR_FATAL;
        goto free_params;
    }
    if (ctx == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        result = SUIT_ERR_FATAL;
        goto free_ctx;
    }
    /*
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    pkey = EVP_PKEY_new();
    EVP_PKEY_keygen(ctx, &pkey);
    */
    /*
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);
    EC_KEY  *ec_key = EC_KEY_new_by_curve_name(nid);
    EC_KEY_set_group(ec_key, ec_group);

    priv = BN_bin2bn(private_key, 32, NULL);
    EC_KEY_set_private_key(ec_key, priv);
    EC_POINT *pub_key_point = EC_POINT_new(ec_group);
    EC_POINT_oct2point(ec_group, pub_key_point, public_key, 65, NULL);
    EC_KEY_set_public_key(ec_key, pub_key_point);
    */

    cose_key->k.key_ptr  = pkey;
    cose_key->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;

free_ctx:
free_params:
out:
    //TODO: free not only pkey but als ctx, params...
    return result;
}

suit_err_t suit_create_es256_key_pair(const unsigned char *private_key, const unsigned char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_openssl_es_key(NID_X9_62_prime256v1, private_key, public_key, cose_key_pair);
}

suit_err_t suit_create_es384_key_pair(const unsigned char *private_key, const unsigned char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_openssl_es_key(NID_secp384r1, private_key, public_key, cose_key_pair);
}

suit_err_t suit_create_es521_key_pair(const unsigned char *private_key, const unsigned char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_openssl_es_key(NID_secp521r1, private_key, public_key, cose_key_pair);
}

suit_err_t suit_create_es256_public_key(const unsigned char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_openssl_es_key(NID_X9_62_prime256v1, NULL, public_key, cose_public_key);
}

suit_err_t suit_create_es384_public_key(const unsigned char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_openssl_es_key(NID_secp384r1, NULL, public_key, cose_public_key);
}

suit_err_t suit_create_es521_public_key(const unsigned char *public_key, struct t_cose_key *cose_public_key) {
    return suit_create_openssl_es_key(NID_secp521r1, NULL, public_key, cose_public_key);
}

suit_err_t suit_free_key(struct t_cose_key *key) {
    EVP_PKEY_free(key->k.key_ptr);
    return SUIT_SUCCESS;
}

#endif /* LIBCSUIT_PSA_CRYPTO_C */

