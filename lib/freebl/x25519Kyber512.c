/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "blapi.h"
#include "secerr.h"
#include "secitem.h"
#include "ecl-priv.h"
#include "ecl-curve.h"

#include "kyber512/api.h"

#define CHECK_OK(func) \
    if (func == NULL)  \
    goto cleanup
#define CHECK_SEC_OK(func)         \
    if (SECSuccess != (rv = func)) \
    return SECFailure

// TODO(goutam): Generate the classical key
// Classical first, then PQ

static SECStatus
gf_populate_params_bytes(ECCurveName name, ECFieldType field_type, ECParams *params)
{
    SECStatus rv = SECFailure;
    const ECCurveBytes *curveParams;

    if ((name < ECCurve_noName) || (name > ECCurve_pastLastCurve))
        goto cleanup;
    params->name = name;
    curveParams = ecCurve_map[params->name];
    CHECK_OK(curveParams);
    params->fieldID.size = curveParams->size;
    params->fieldID.type = field_type;
    if (field_type != ec_field_GFp && field_type != ec_field_plain) {
        return SECFailure;
    }
    params->fieldID.u.prime.len = curveParams->scalarSize;
    params->fieldID.u.prime.data = (unsigned char *)curveParams->irr;
    params->curve.a.len = curveParams->scalarSize;
    params->curve.a.data = (unsigned char *)curveParams->curvea;
    params->curve.b.len = curveParams->scalarSize;
    params->curve.b.data = (unsigned char *)curveParams->curveb;
    params->base.len = curveParams->pointSize;
    params->base.data = (unsigned char *)curveParams->base;
    params->order.len = curveParams->scalarSize;
    params->order.data = (unsigned char *)curveParams->order;
    params->cofactor = curveParams->cofactor;

    rv = SECSuccess;

cleanup:
    return rv;
}

SECStatus
X25519Kyber512Draft00_Generate(SECItem **publicKey, SECItem **secretKey)
{
    SECStatus rv = SECFailure;

    ECParams *params;
    PLArenaPool *arena;
    if (!(arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE)))
        return SECFailure;
    params = (ECParams *)PORT_ArenaZAlloc(arena, sizeof(ECParams));
    if (!params) {
        PORT_FreeArena(arena, PR_TRUE);
        return SECFailure;
    }

    CHECK_SEC_OK(gf_populate_params_bytes(ECCurve25519, ec_field_plain, params));

    ECPrivateKey *x25519Key = NULL;
    CHECK_SEC_OK(EC_NewKey(params, &x25519Key));

    *publicKey = SECITEM_AllocItem(NULL, *publicKey, x25519Key->publicValue.len + PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    if (*publicKey == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    *secretKey = SECITEM_AllocItem(NULL, *secretKey, x25519Key->privateValue.len + PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES);
    if (*secretKey == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    /* Write out classical part first */
    memcpy((*publicKey)->data, x25519Key->publicValue.data, 32);
    memcpy((*secretKey)->data, x25519Key->privateValue.data, 32);

    /* Generate PQ key */
    int rc = PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair((*publicKey)->data + x25519Key->publicValue.len,
                                                       (*secretKey)->data + x25519Key->privateValue.len);
    if (rc != 0) {
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus
X25519Kyber512Draft00_Encapsulate(SECItem **ciphertext, SECItem **sharedSecret, SECItem *publicKey)
{
    SECStatus rv = SECFailure;
    ECParams params;
    CHECK_SEC_OK(gf_populate_params_bytes(ECCurve25519, ec_field_plain, &params));
    ECPrivateKey *x25519Key;
    CHECK_SEC_OK(EC_NewKey(&params, &x25519Key));

    *ciphertext = SECITEM_AllocItem(NULL, *ciphertext, x25519Key->publicValue.len + PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    if (*ciphertext == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    *sharedSecret = SECITEM_AllocItem(NULL, *sharedSecret, 32 + PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES);
    if (*sharedSecret == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    ec_Curve25519_mul((*sharedSecret)->data, x25519Key->privateValue.data, publicKey->data);

    memcpy((*ciphertext)->data, x25519Key->publicValue.data, 32);
    int rc = PQCLEAN_KYBER512_CLEAN_crypto_kem_enc((*ciphertext)->data + x25519Key->publicValue.len, (*sharedSecret)->data + 32, publicKey->data);
    if (rc != 0) {
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus
X25519Kyber512Draft00_Decapsulate(SECItem **sharedSecret, SECItem *ciphertext, SECItem *secretKey)
{
    *sharedSecret = SECITEM_AllocItem(NULL, *sharedSecret, 32 + PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES);
    if (*sharedSecret == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    ec_Curve25519_mul((*sharedSecret)->data, secretKey->data, ciphertext->data);


    int rc = PQCLEAN_KYBER512_CLEAN_crypto_kem_dec((*sharedSecret)->data + 32, ciphertext->data + 32, secretKey->data + 32);
    if (rc != 0) {
        return SECFailure;
    }

    return SECSuccess;
}
