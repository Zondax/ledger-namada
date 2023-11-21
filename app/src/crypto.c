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
#include "leb128.h"
#include "cx_sha256.h"

#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE (SIGN_PREFIX_SIZE + CX_SHA256_SIZE)

#define MAX_SIGNATURE_HASHES 10

static zxerr_t crypto_extractPublicKey_ed25519(uint8_t *pubKey, uint16_t pubKeyLen) {
    if (pubKey == NULL || pubKeyLen < PK_LEN_25519) {
        return zxerr_invalid_crypto_settings;
    }
    zxerr_t error = zxerr_unknown;
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[2 * SK_LEN_25519] = {0};

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0))

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SK_LEN_25519, &cx_privateKey))
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey))
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1))
    for (unsigned int i = 0; i < PK_LEN_25519; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }

    if ((cx_publicKey.W[PK_LEN_25519] & 1) != 0) {
        pubKey[31] |= 0x80;
    }
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }
    return error;
}

static zxerr_t crypto_sign_ed25519(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen) {
    if (output == NULL || message == NULL || outputLen < ED25519_SIGNATURE_SIZE || messageLen == 0) {
        return zxerr_unknown;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[2 * SK_LEN_25519] = {0};

    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0))

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SK_LEN_25519, &cx_privateKey))
    CATCH_CXERROR(cx_eddsa_sign_no_throw(&cx_privateKey,
                                         CX_SHA512,
                                         message,
                                         messageLen,
                                         output,
                                         outputLen))
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

typedef struct {
    uint8_t publicKey[PK_LEN_25519_PLUS_TAG];
    uint8_t address[ADDRESS_LEN_TESTNET];
} __attribute__((packed)) ed25519_answer_t;

zxerr_t crypto_fillAddress_ed25519(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen)
{
    zemu_log("crypto_fillAddress_ed25519");
    MEMZERO(buffer, bufferLen);
    uint8_t outLen = 0;
    ed25519_answer_t *const answer = (ed25519_answer_t *) buffer;

    if (bufferLen < PK_LEN_25519_PLUS_TAG + ADDRESS_LEN_TESTNET) {
        return zxerr_unknown;
    }
    CHECK_ZXERR(crypto_extractPublicKey_ed25519(answer->publicKey + 1, PK_LEN_25519))

    const bool isTestnet = hdPath[1] == HDPATH_1_TESTNET;
    outLen = crypto_encodePubkey_ed25519(answer->address, sizeof(answer->address), answer->publicKey + 1, isTestnet);

    if (outLen == 0) {
        MEMZERO(buffer, bufferLen);
        return zxerr_encoding_failed;
    }

    *addrResponseLen = PK_LEN_25519_PLUS_TAG + outLen;
    return zxerr_ok;
}

zxerr_t crypto_fillAddress(signing_key_type_e addressKind, uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen)
{
    zxerr_t err = zxerr_unknown;
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

static zxerr_t crypto_hashFeeHeader(const header_t *header, uint8_t *output, uint32_t outputLen) {
    if (header == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    const uint8_t discriminant = 0x07;
    cx_sha256_update(&sha256, &discriminant, sizeof(discriminant));
    cx_sha256_update(&sha256, header->extBytes.ptr, header->extBytes.len);
    cx_sha256_final(&sha256, output);
    return zxerr_ok;
}


static zxerr_t crypto_hashRawHeader(const header_t *header, uint8_t *output, uint32_t outputLen) {
    if (header == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    const uint8_t discriminant = 0x07;
    cx_sha256_update(&sha256, &discriminant, sizeof(discriminant));
    cx_sha256_update(&sha256, header->bytes.ptr, header->bytes.len);
    const uint8_t header_discriminant = 0x00;
    cx_sha256_update(&sha256, &header_discriminant, sizeof(header_discriminant));
    cx_sha256_final(&sha256, output);
    return zxerr_ok;
}

zxerr_t crypto_hashSigSection(const signature_section_t *signature_section, const uint8_t *prefix, uint32_t prefixLen, uint8_t *output, uint32_t outputLen) {
    if (signature_section == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }

    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    if (prefix != NULL) {
        cx_sha256_update(&sha256, prefix, prefixLen);
    }
    cx_sha256_update(&sha256, (uint8_t*) &signature_section->hashes.hashesLen, 4);
    cx_sha256_update(&sha256, signature_section->hashes.hashes.ptr, HASH_LEN * signature_section->hashes.hashesLen);
    cx_sha256_update(&sha256, (uint8_t*) &signature_section->signerDiscriminant, 1);

    switch (signature_section->signerDiscriminant) {
        case PubKeys:
            cx_sha256_update(&sha256, (uint8_t*) &signature_section->pubKeysLen, 4);
            if (signature_section->pubKeysLen > 0) {
                cx_sha256_update(&sha256, signature_section->pubKeys.ptr, PK_LEN_25519_PLUS_TAG * signature_section->pubKeysLen);
            }
            break;

        case Address:
            cx_sha256_update(&sha256, (uint8_t*) &signature_section->address.ptr, signature_section->address.len);
            break;

        default:
            return zxerr_invalid_crypto_settings;
    }

    cx_sha256_update(&sha256, (const uint8_t*) &signature_section->signaturesLen, 4);
    if(signature_section->signaturesLen > 0) {
        cx_sha256_update(&sha256, signature_section->indexedSignatures.ptr, signature_section->indexedSignatures.len);
    }
    cx_sha256_final(&sha256, output);
    return zxerr_ok;
}

static zxerr_t crypto_addTxnHashes(const parser_tx_t *txObj, concatenated_hashes_t *hashes) {
    if (txObj == NULL || hashes == NULL) {
        return zxerr_unknown;
    }

    // Append additional sections depending on the transaction type
    switch (txObj->typeTx) {
        case InitAccount:
            MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->initAccount.vp_type_sechash.ptr, HASH_LEN);
            hashes->indices.ptr[hashes->hashesLen] = txObj->initAccount.vp_type_secidx;
            hashes->hashesLen++;
            break;

        case InitValidator:
            MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->initValidator.vp_type_sechash.ptr, HASH_LEN);
            hashes->indices.ptr[hashes->hashesLen] = txObj->initValidator.vp_type_secidx;
            hashes->hashesLen++;
            break;

        case UpdateVP:
            MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->updateVp.vp_type_sechash.ptr, HASH_LEN);
            hashes->indices.ptr[hashes->hashesLen] = txObj->updateVp.vp_type_secidx;
            hashes->hashesLen++;
            break;

        case InitProposal:
            MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->initProposal.content_sechash.ptr, HASH_LEN);
            hashes->indices.ptr[hashes->hashesLen] = txObj->initProposal.content_secidx;
            hashes->hashesLen++;
            if (txObj->initProposal.has_proposal_code) {
                MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->initProposal.proposal_code_sechash.ptr, HASH_LEN);
                hashes->indices.ptr[hashes->hashesLen] = txObj->initProposal.proposal_code_secidx;
                hashes->hashesLen++;
            }
            break;

        default:
            // Other transaction types do not have extra data
            break;
    }

    return zxerr_ok;
}


zxerr_t crypto_sign(const parser_tx_t *txObj, uint8_t *output, uint16_t outputLen) {
    const uint16_t minimumBufferSize = PK_LEN_25519_PLUS_TAG + 2 * SALT_LEN + 2 * SIG_LEN_25519_PLUS_TAG + 2 + 10;

    if (txObj == NULL || output == NULL || outputLen < minimumBufferSize) {
        return zxerr_unknown;
    }
    MEMZERO(output, outputLen);
    CHECK_ZXERR(crypto_extractPublicKey_ed25519(output + 1, PK_LEN_25519))
    const bytes_t pubkey = {.ptr = output, .len = PK_LEN_25519_PLUS_TAG};

    // Hashes: code, data, (initAcc | initVali | updateVP = 1  /  initProp = 2), raw_signature, header ---> MaxHashes = 6
    uint8_t hashes_buffer[MAX_SIGNATURE_HASHES * HASH_LEN] = {0};
    uint8_t indices_buffer[MAX_SIGNATURE_HASHES] = {0};
    concatenated_hashes_t section_hashes = {
        .hashes.ptr = hashes_buffer,
        .hashes.len = sizeof(hashes_buffer),
        .indices.ptr = indices_buffer,
        .indices.len = sizeof(indices_buffer),
        .hashesLen = 0
    };

    uint8_t *rawHeaderHash = section_hashes.hashes.ptr;
    section_hashes.indices.ptr[0] = 255;
    // Concatenate the raw header hash
    CHECK_ZXERR(crypto_hashRawHeader(&txObj->transaction.header, rawHeaderHash, HASH_LEN))
    section_hashes.hashesLen = 1;

    char hexString[100] = {0};
    array_to_hexstr(hexString, sizeof(hexString), section_hashes.hashes.ptr, HASH_LEN);
    ZEMU_LOGF(100, "Raw header hash: %s\n", hexString);

    CHECK_ZXERR(crypto_addTxnHashes(txObj, &section_hashes))

    // Construct the salt for the signature section being constructed
    uint8_t *salt_buffer = output + PK_LEN_25519_PLUS_TAG;
    const bytes_t salt = {.ptr = salt_buffer, .len = SALT_LEN};

    // Construct the unsigned variant of the raw signature section
    signature_section_t signature_section = {
        .salt = salt,
        .hashes = section_hashes,
        .signerDiscriminant = PubKeys,
        .pubKeysLen = 0,
        .pubKeys = pubkey,
        .signaturesLen = 0,
        .indexedSignatures = {NULL, 0},
    };

    // Hash the unsigned signature section
    uint8_t *raw_signature_hash = section_hashes.hashes.ptr + (section_hashes.hashesLen * HASH_LEN);
    CHECK_ZXERR(crypto_hashSigSection(&signature_section, NULL, 0, raw_signature_hash, HASH_LEN))

    // Sign over the hash of the unsigned signature section
    uint8_t *raw = salt_buffer + SALT_LEN;
    CHECK_ZXERR(crypto_sign_ed25519(raw + 1, ED25519_SIGNATURE_SIZE, raw_signature_hash, HASH_LEN))

    uint8_t raw_indices_len = section_hashes.hashesLen;
    uint8_t raw_indices_buffer[MAX_SIGNATURE_HASHES] = {0};
    MEMCPY(raw_indices_buffer, section_hashes.indices.ptr, section_hashes.hashesLen);

    // ----------------------------------------------------------------------
    // Start generating wrapper signature
    // Affix the signature to make the signature section signed
    signature_section.signaturesLen = 1;
    //Use previous byte from salt that is always 0x00 but we're not sending an extra byte in the response since raw points to output buffer
    signature_section.indexedSignatures.ptr = raw - 1;
    signature_section.indexedSignatures.len = 1 + SIG_LEN_25519_PLUS_TAG;
    signature_section.pubKeysLen = 1;

    // Compute the hash of the signed signature section and concatenate it
    const uint8_t sig_sec_prefix = 0x03;
    CHECK_ZXERR(crypto_hashSigSection(&signature_section, &sig_sec_prefix, 1, raw_signature_hash, HASH_LEN))
    section_hashes.indices.ptr[section_hashes.hashesLen] = txObj->transaction.sections.sectionLen+1+0 /*signature_raw*/;
    section_hashes.hashesLen++;
    signature_section.hashes.hashesLen++;

    /// Hash the header section
    uint8_t *header_hash = section_hashes.hashes.ptr;
    CHECK_ZXERR(crypto_hashFeeHeader(&txObj->transaction.header, header_hash, HASH_LEN))
    section_hashes.indices.ptr[0] = 0;

    // Hash the code and data sections
    const section_t *data = &txObj->transaction.sections.data;
    const section_t *code = &txObj->transaction.sections.code;
    uint8_t *codeHash = section_hashes.hashes.ptr + (section_hashes.hashesLen * HASH_LEN);
    uint8_t *dataHash = codeHash + HASH_LEN;
    section_hashes.indices.ptr[section_hashes.hashesLen] = code->idx;
    section_hashes.indices.ptr[section_hashes.hashesLen+1] = data->idx;
    // Concatenate the code and data section hashes
    CHECK_ZXERR(crypto_hashCodeSection(code, codeHash, HASH_LEN))
    CHECK_ZXERR(crypto_hashDataSection(data, dataHash, HASH_LEN))
    section_hashes.hashesLen += 2;
    signature_section.hashes.hashesLen += 2;


    // Hash the eligible signature sections
    for (uint32_t i = 0; i < txObj->transaction.sections.signaturesLen; i++) {
        const signature_section_t *prev_sig = &txObj->transaction.sections.signatures[i];
        unsigned int j;

        // Ensure that we recognize each hash that was signed over
        for (j = 0; j < prev_sig->hashes.hashesLen; j++) {
            unsigned int k;
            // Check if we know the hash that was signed over
            for (k = 0; k < signature_section.hashes.hashesLen; k++) {
                if (!memcmp(prev_sig->hashes.hashes.ptr, signature_section.hashes.hashes.ptr, HASH_LEN)) {
                    break;
                }
            }
            // If loop counter makes it to end, then this hash was not recognized
            if (k == signature_section.hashes.hashesLen) {
                break;
            }
        }

        // If loop counter doesn't make it to end, then a hash was not recognized
        if (j != prev_sig->hashes.hashesLen) {
            continue;
        }

        // We sign over a signature if it signs over hashes that we recognize
        uint8_t *prev_sig_hash = section_hashes.hashes.ptr + (section_hashes.hashesLen * HASH_LEN);
        CHECK_ZXERR(crypto_hashSigSection(prev_sig, &sig_sec_prefix, 1, prev_sig_hash, HASH_LEN))
        section_hashes.indices.ptr[section_hashes.hashesLen] = prev_sig->idx;
        section_hashes.hashesLen++;
        signature_section.hashes.hashesLen++;
    }

    signature_section.signaturesLen = 0;
    signature_section.pubKeysLen = 0;
    // Hash the unsigned signature section into raw_sig_hash
    uint8_t wrapper_sig_hash[HASH_LEN] = {0};
    CHECK_ZXERR(crypto_hashSigSection(&signature_section, NULL, 0, wrapper_sig_hash, sizeof(wrapper_sig_hash)))

    // Sign over the hash of the unsigned signature section
    uint8_t *wrapper = raw + SALT_LEN + SIG_LEN_25519_PLUS_TAG;
    CHECK_ZXERR(crypto_sign_ed25519(wrapper + 1, ED25519_SIGNATURE_SIZE, wrapper_sig_hash, sizeof(wrapper_sig_hash)))

#if defined(DEBUG_HASHES)
    ZEMU_LOGF(100, "------------------------------------------------\n");
    for (uint8_t i = 0; i < section_hashes.hashesLen; i++) {
        char hexString[100] = {0};
        array_to_hexstr(hexString, sizeof(hexString), section_hashes.hashes.ptr + (HASH_LEN * i), HASH_LEN);
        ZEMU_LOGF(100, "Hash %d: %s\n", i, hexString);
    }
    ZEMU_LOGF(100, "------------------------------------------------\n");
#endif

    uint8_t *indices = wrapper + SIG_LEN_25519_PLUS_TAG;
    *indices = raw_indices_len;
    MEMCPY(indices + 1, raw_indices_buffer, raw_indices_len);
    indices += 1 + raw_indices_len;
    *indices = section_hashes.hashesLen;
    MEMCPY(indices + 1, section_hashes.indices.ptr, section_hashes.hashesLen);

    return zxerr_ok;
}
