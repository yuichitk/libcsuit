#include "csuit/suit_common.h"
#include "csuit/suit_cose.h"

#if defined(LIBCSUIT_PSA_CRYPTO_C)
int32_t suit_create_es_key_pair(int nid, const char *private_key, const char *dummy, struct t_cose_key *cose_key_pair) {
    //psa_key_type
    return SUIT_SUCCESS;
}
#else /* !LIBCSUIT_PSA_CRYPTO_C */
int32_t suit_create_es_key_pair(int nid, const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
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

    cose_key_pair->k.key_ptr  = ec_key;
    cose_key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return SUIT_SUCCESS;
}

int32_t suit_create_es256_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_es_key_pair(NID_X9_62_prime256v1, private_key, public_key, cose_key_pair);
}

int32_t suit_create_es384_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_es_key_pair(NID_secp384r1, private_key, public_key, cose_key_pair);
}

int32_t suit_create_es521_key_pair(const char *private_key, const char *public_key, struct t_cose_key *cose_key_pair) {
    return suit_create_es_key_pair(NID_secp521r1, private_key, public_key, cose_key_pair);
}
#endif

