/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "bech32.h"
#include "crypto.h"
#include "coin.h"
#include "cx.h"
#include "tx.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "crypto_helper.h"

#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE (SIGN_PREFIX_SIZE + CX_SHA256_SIZE)

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) rsv_signature_t;

zxerr_t crypto_extractPublicKey_ed25519(uint8_t *pubKey, uint16_t pubKeyLen)
{
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519];

    if (pubKeyLen < PK_LEN_25519) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32_seed_key(
                    HDW_NORMAL,
                    CX_CURVE_Ed25519,
                    hdPath,
                    HDPATH_LEN_DEFAULT,
                    privateKeyData,
                    NULL,
                    NULL,
                    0);

            cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1);
            for (unsigned int i = 0; i < PK_LEN_25519; i++) {
                pubKey[i] = cx_publicKey.W[64 - i];
            }
            if ((cx_publicKey.W[PK_LEN_25519] & 1) != 0) {
                pubKey[31] |= 0x80;
            }
        }
        CATCH_ALL
        {
            err = zxerr_ledger_api_error;
        }
        FINALLY
        {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, SK_LEN_25519);
        }
    }
    END_TRY;

    return err;
}

zxerr_t crypto_extractPublicKey_secp256k1(uint8_t *pubKey, uint16_t pubKeyLen)
{
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SECP256K1_SK_LEN] = {0};

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       hdPath,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, SECP256K1_SK_LEN, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
            memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
        }
        CATCH_ALL {
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, SECP256K1_SK_LEN);
        }

    }
    END_TRY;
    return err;
}

zxerr_t crypto_sign_ed25519(uint8_t *signature, uint16_t signatureMaxLen, const uint8_t *message, uint16_t messageLen)
{
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32_seed_key(
                    HDW_NORMAL,
                    CX_CURVE_Ed25519,
                    hdPath,
                    HDPATH_LEN_DEFAULT,
                    privateKeyData,
                    NULL,
                    NULL,
                    0);

            cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, SCALAR_LEN_ED25519, &cx_privateKey);

            // Sign
            cx_eddsa_sign(&cx_privateKey,
                          CX_LAST,
                          CX_SHA512,
                          message,
                          messageLen,
                          NULL,
                          0,
                          signature,
                          signatureMaxLen,
                          NULL);

        }
        CATCH_ALL
        {
            err = zxerr_unknown;
        }
        FINALLY
        {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, SK_LEN_25519);
        }
    }
    END_TRY;

    return err;
}

zxerr_t crypto_sign_secp256k1(uint8_t *signature,
                    uint16_t signatureMaxLen,
                    uint16_t *sigSize) {
    if (signatureMaxLen < SIGN_PREHASH_SIZE + sizeof(rsv_signature_t)){
        return zxerr_buffer_too_small;
    }

    uint8_t messageDigest[CX_SHA256_SIZE];
    MEMZERO(messageDigest,sizeof(messageDigest));

    // Hash the message to be signed
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLen = tx_get_buffer_length();
    cx_hash_sha256(message, messageLen, messageDigest, CX_SHA256_SIZE);

    CHECK_APP_CANARY()


    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SECP256K1_SK_LEN];
    unsigned int info = 0;
    int signatureLength = 0;

    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_SECP256K1,
                                       hdPath,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_SECP256K1, privateKeyData, SECP256K1_SK_LEN, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            messageDigest,
                                            CX_SHA256_SIZE,
                                            signature,
                                            signatureMaxLen,
                                            &info);

        // TODO: DO WE NEED TO CONVERT DER TO RSV?
        }
        CATCH_ALL {
            signatureLength = 0;
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, SECP256K1_SK_LEN);
        }
    }
    END_TRY;

    *sigSize = signatureLength;
    return err;
}


typedef struct {
    uint8_t publicKey[PK_LEN_25519];
    uint8_t address[ADDRESS_LEN_TESTNET];
} __attribute__((packed)) ed25519_answer_t;

zxerr_t crypto_fillAddress_ed25519(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen)
{
    zemu_log("crypto_fillAddress_ed25519");
    MEMZERO(buffer, bufferLen);
    uint8_t outLen = 0;
    ed25519_answer_t *const answer = (ed25519_answer_t *) buffer;

    if (bufferLen < PK_LEN_25519 + ADDRESS_LEN_TESTNET) {
        return zxerr_unknown;
    }
    CHECK_ZXERR(crypto_extractPublicKey_ed25519(answer->publicKey, sizeof_field(ed25519_answer_t, publicKey)))

    const bool isTestnet = hdPath[1] == HDPATH_1_TESTNET;
    outLen = crypto_encodePubkey_ed25519(answer->address, sizeof(answer->address), answer->publicKey, isTestnet);

    if (outLen == 0) {
        MEMZERO(buffer, bufferLen);
        return zxerr_encoding_failed;
    }

    *addrResponseLen = PK_LEN_25519 + outLen;
    return zxerr_ok;
}

zxerr_t crypto_fillAddress(signing_key_type_e addressKind, uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen)
{
    zxerr_t err = zxerr_ok;
    switch (addressKind) {
        case key_ed25519:
            err = crypto_fillAddress_ed25519(buffer, bufferLen, addrResponseLen);
            break;
        case key_secp256k1:
            // TODO
            break;
    }
    return err;
}

zxerr_t crypto_signOuterLayerTxn(const outer_layer_tx_t *outerTxn, uint8_t *output, uint16_t outputLen) {
    if (outerTxn == NULL || output == NULL) {
        return zxerr_no_data;
    }

    if (outputLen < ED25519_SIGNATURE_SIZE) {
        return zxerr_buffer_too_small;
    }

    // 1 - Serialize transaction and hash it
    uint8_t bytes_to_sign[CX_SHA256_SIZE] = {0};
    CHECK_ZXERR(crypto_getBytesToSign(outerTxn, bytes_to_sign, sizeof(bytes_to_sign)))

#ifdef APP_TESTING
    uint8_t tmpArray[65] = {0};
    array_to_hexstr_uppercase(tmpArray, sizeof(tmpArray), bytes_to_sign, sizeof(bytes_to_sign));
    ZEMU_LOGF(100, "bytes_to_sign: %s\n", (char*)tmpArray)
#endif

    // 2 - Sign ED25519
    CHECK_ZXERR(crypto_sign_ed25519(output, outputLen, bytes_to_sign, sizeof(bytes_to_sign)))

    return zxerr_ok;
}
