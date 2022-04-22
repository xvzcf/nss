/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "blapi.h"
#include "secerr.h"
#include "secitem.h"

#include "kyber512/api.h"

// TODO(goutam): Generate the classical key

SECStatus
CECPQ3_Generate(SECItem **publicKey, SECItem **secretKey)
{
    *publicKey = SECITEM_AllocItem(NULL, *publicKey, PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    if (publicKey == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    *secretKey = SECITEM_AllocItem(NULL, *secretKey, PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES);
    if (secretKey == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    /* Generate PQ key */
    int rc = PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair((*publicKey)->data, (*secretKey)->data);
    if (rc != 0) {
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus
CECPQ3_Encapsulate(SECItem **ciphertext, SECItem **sharedSecret, SECItem *publicKey)
{
    *ciphertext = SECITEM_AllocItem(NULL, *ciphertext, PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    if (ciphertext == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    *sharedSecret = SECITEM_AllocItem(NULL, *sharedSecret, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES);
    if (sharedSecret == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    int rc = PQCLEAN_KYBER512_CLEAN_crypto_kem_enc((*ciphertext)->data, (*sharedSecret)->data, publicKey->data);
    if (rc != 0) {
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus
CECPQ3_Decapsulate(SECItem **sharedSecret, SECItem *ciphertext, SECItem *secretKey)
{
    *sharedSecret = SECITEM_AllocItem(NULL, *sharedSecret, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES);
    if (sharedSecret == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    int rc = PQCLEAN_KYBER512_CLEAN_crypto_kem_dec((*sharedSecret)->data, ciphertext->data, secretKey->data);
    if (rc != 0) {
        return SECFailure;
    }

    return SECSuccess;
}
