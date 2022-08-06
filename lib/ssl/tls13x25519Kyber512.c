/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secitem.h"
#include "sslimpl.h"
#include "pk11func.h"
#include "blapi.h"

SECStatus
tls13_GenerateX25519Kyber512Draft00KeyPair(const sslSocket *ss,
                            const sslNamedGroupDef *group,
                            sslEphemeralKeyPair **keyPair)
{
    SECKEYPrivateKey *privKey = NULL;
    SECKEYPublicKey *pubKey = NULL;
    sslEphemeralKeyPair *pair;

    PK11SlotInfo *slot = PK11_GetBestSlot(CKM_NSS_X25519KYBER512DRAFT00_KEY_GEN, NULL);
    if (!slot) {
        return SECFailure;
    }

    privKey = PK11_GenerateKeyPair(slot, CKM_NSS_X25519KYBER512DRAFT00_KEY_GEN, NULL, &pubKey,
                                 PR_FALSE, PR_FALSE, NULL);
    PK11_FreeSlot(slot);


    if (!privKey || !pubKey ||
        !(pair = ssl_NewEphemeralKeyPair(group, privKey, pubKey))) {
        if (privKey) {
            SECKEY_DestroyPrivateKey(privKey);
        }
        if (pubKey) {
            SECKEY_DestroyPublicKey(pubKey);
        }
        ssl_MapLowLevelError(SEC_ERROR_KEYGEN_FAIL);
        return SECFailure;
    }

    *keyPair = pair;

    return SECSuccess;
}
