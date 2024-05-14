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
#include "parser_impl_common.h"
#include "parser_impl_masp.h"
#include "signhash.h"
#include "rslib.h"
#include "keys_def.h"
#include "keys_personalizations.h"
#include "nvdata.h"

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    #include "cx.h"
    #include "cx_sha256.h"
    #include "cx_blake2b.h"
#else
    #include "picohash.h"
    #include "blake2.h"
    #define CX_SHA256_SIZE 32
#endif
#include "blake2.h"

#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE (SIGN_PREFIX_SIZE + CX_SHA256_SIZE)

#define MAX_SIGNATURE_HASHES 10

#define CHECK_PARSER_OK(CALL)      \
  do {                         \
    cx_err_t __cx_err = CALL;  \
    if (__cx_err != parser_ok) {   \
      return zxerr_unknown;    \
    }                          \
  } while (0)

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
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SK_LEN_25519, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1));
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
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SK_LEN_25519, &cx_privateKey));
    CATCH_CXERROR(cx_eddsa_sign_no_throw(&cx_privateKey,
                                         CX_SHA512,
                                         message,
                                         messageLen,
                                         output,
                                         outputLen));
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

zxerr_t crypto_fillAddress_ed25519(uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen) {
    if (buffer == NULL || cmdResponseLen == NULL) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    // Testnet pubkeys and addresses are larger than those on the mainnet. Consider the worst-case scenario
    if (bufferLen < PK_LEN_25519_PLUS_TAG + PUBKEY_LEN_TESTNET + ADDRESS_LEN_TESTNET + 2) {
        return zxerr_unknown;
    }

    // getAddress response[rawPubkey(33) | pubkey len(1) | pubkey(?) | address len(1) | address(?)]
    uint8_t *rawPubkey = buffer;
    CHECK_ZXERR(crypto_extractPublicKey_ed25519(rawPubkey+1, PK_LEN_25519));

    // Encode and copy in output buffer pubkey
    uint8_t *pubkey = buffer + PK_LEN_25519_PLUS_TAG;
    CHECK_ZXERR(crypto_encodeRawPubkey(rawPubkey, PK_LEN_25519_PLUS_TAG, pubkey, bufferLen - PK_LEN_25519_PLUS_TAG));

    // Encode and copy in output buffer address
    uint8_t *address = pubkey + *pubkey + 1;
    const uint16_t remainingBufferSpace = bufferLen - PK_LEN_25519_PLUS_TAG - *pubkey - 1;
    CHECK_ZXERR(crypto_encodeAddress(rawPubkey + 1, PK_LEN_25519, address, remainingBufferSpace));

    *cmdResponseLen = PK_LEN_25519_PLUS_TAG + *pubkey + *address + 2;
    return zxerr_ok;
}

zxerr_t crypto_fillAddress(signing_key_type_e addressKind, uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen)
{
    zxerr_t err = zxerr_unknown;
    switch (addressKind) {
        case key_ed25519:
            err = crypto_fillAddress_ed25519(buffer, bufferLen, cmdResponseLen);
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
    CHECK_CX_OK(cx_sha256_update(&sha256, &discriminant, sizeof(discriminant)));
    CHECK_CX_OK(cx_sha256_update(&sha256, header->extBytes.ptr, header->extBytes.len));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
    return zxerr_ok;
}


static zxerr_t crypto_hashRawHeader(const header_t *header, uint8_t *output, uint32_t outputLen) {
    if (header == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    const uint8_t discriminant = 0x07;
    CHECK_CX_OK(cx_sha256_update(&sha256, &discriminant, sizeof(discriminant)));
    CHECK_CX_OK(cx_sha256_update(&sha256, header->bytes.ptr, header->bytes.len));
    const uint8_t header_discriminant = 0x00;
    CHECK_CX_OK(cx_sha256_update(&sha256, &header_discriminant, sizeof(header_discriminant)));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
    return zxerr_ok;
}

zxerr_t crypto_hashSigSection(const signature_section_t *signature_section, const uint8_t *prefix, uint32_t prefixLen, uint8_t *output, uint32_t outputLen) {
    if (signature_section == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }

    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    if (prefix != NULL) {
        CHECK_CX_OK(cx_sha256_update(&sha256, prefix, prefixLen));
    }
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &signature_section->hashes.hashesLen, 4));
    CHECK_CX_OK(cx_sha256_update(&sha256, signature_section->hashes.hashes.ptr, HASH_LEN * signature_section->hashes.hashesLen));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &signature_section->signerDiscriminant, 1));

    switch (signature_section->signerDiscriminant) {
        case PubKeys: {
            CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &signature_section->pubKeysLen, 4));
            uint32_t pos = 0;
            for (uint32_t i = 0; i < signature_section->pubKeysLen; i++) {
                uint8_t tag = signature_section->pubKeys.ptr[pos++];
                if (tag != key_ed25519 && tag != key_secp256k1) {
                    return zxerr_unknown;
                }
                // Skip the public key's type tag
                const uint8_t pubKeySize = tag == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN;
                // Skip the signature proper
                pos += pubKeySize;
            }
            if(pos > 0) {
                CHECK_CX_OK(cx_sha256_update(&sha256, signature_section->pubKeys.ptr, pos));
            }
            break;
        }
        case Address:
            CHECK_CX_OK(cx_sha256_update(&sha256, signature_section->addressBytes.ptr, signature_section->addressBytes.len));
            break;

        default:
            return zxerr_invalid_crypto_settings;
    }

    CHECK_CX_OK(cx_sha256_update(&sha256, (const uint8_t*) &signature_section->signaturesLen, 4));
    uint32_t pos = 0;
    for (uint32_t i = 0; i < signature_section->signaturesLen; i++) {
        // Skip the signature's 1 byte index
        pos++;
        uint8_t tag = signature_section->indexedSignatures.ptr[pos++];
        if (tag != key_ed25519 && tag != key_secp256k1) {
            return zxerr_unknown;
        }
        // Skip the signature's type tag
        const uint8_t signatureSize = tag == key_ed25519 ? ED25519_SIGNATURE_SIZE : SIG_SECP256K1_LEN;
        // Skip the signature proper
        pos += signatureSize;
    }
    if(pos > 0) {
        CHECK_CX_OK(cx_sha256_update(&sha256, signature_section->indexedSignatures.ptr, pos));
    }
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
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

        case UpdateVP:
            MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->updateVp.vp_type_sechash.ptr, HASH_LEN);
            hashes->indices.ptr[hashes->hashesLen] = txObj->updateVp.vp_type_secidx;
            hashes->hashesLen++;
            break;

        case InitProposal:
            MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->initProposal.content_sechash.ptr, HASH_LEN);
            hashes->indices.ptr[hashes->hashesLen] = txObj->initProposal.content_secidx;
            hashes->hashesLen++;
            if (txObj->initProposal.proposal_type == DefaultWithWasm) {
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

    // Include the memo section hash in the signature if it's there
    if (txObj->transaction.header.memoSection != NULL) {
        const section_t *memo = txObj->transaction.header.memoSection;
        uint8_t *memoHash = section_hashes.hashes.ptr + (section_hashes.hashesLen * HASH_LEN);
        section_hashes.indices.ptr[section_hashes.hashesLen] = memo->idx;
        CHECK_ZXERR(crypto_hashExtraDataSection(memo, memoHash, HASH_LEN))
        section_hashes.hashesLen++;
        signature_section.hashes.hashesLen++;
    }

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

    /// Hash the header section
    uint8_t *header_hash = section_hashes.hashes.ptr;
    CHECK_ZXERR(crypto_hashFeeHeader(&txObj->transaction.header, header_hash, HASH_LEN))
    section_hashes.indices.ptr[0] = 0;

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

// MASP
static zxerr_t computeKeys(keys_t * saplingKeys) {
    if (saplingKeys == NULL) {
        return zxerr_no_data;
    }

    // Compute ask, nsk, ovk
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_ASK, saplingKeys->ask, true));
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_NSK, saplingKeys->nsk, true));
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_OVK, saplingKeys->ovk, true));

    // Compute diversifier key - dk
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_DK, saplingKeys->dk, true));

    // Compute ak, nk, ivk
    CHECK_PARSER_OK(generate_key(saplingKeys->ask, SpendingKeyGenerator, saplingKeys->ak));
    CHECK_PARSER_OK(generate_key(saplingKeys->nsk, ProofGenerationKeyGenerator, saplingKeys->nk));
    CHECK_PARSER_OK(computeIVK(saplingKeys->ak, saplingKeys->nk, saplingKeys->ivk));

    // Compute diversifier
    CHECK_PARSER_OK(computeDiversifier(saplingKeys->dk, saplingKeys->diversifier_start_index, saplingKeys->diversifier));

    // Compute address
    CHECK_PARSER_OK(computePkd(saplingKeys->ivk, saplingKeys->diversifier, saplingKeys->address));

    return zxerr_ok;
}

__Z_INLINE zxerr_t copyKeys(keys_t *saplingKeys, key_kind_e requestedKeys, uint8_t *output, uint16_t outputLen) {
    if (saplingKeys == NULL || output == NULL) {
        return zxerr_no_data;
    }

    switch (requestedKeys) {
        case PublicAddress:
            if (outputLen < KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->address, KEY_LENGTH);
            break;

        case ViewKeys:
            if (outputLen < 4 * KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->ak, KEY_LENGTH);
            memcpy(output + KEY_LENGTH, saplingKeys->nk, KEY_LENGTH);
            memcpy(output + 2 * KEY_LENGTH, saplingKeys->ovk, KEY_LENGTH);
            memcpy(output + 3 * KEY_LENGTH, saplingKeys->ivk, KEY_LENGTH);
            break;

        case ProofGenerationKey:
            if (outputLen < 2 * KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->ak, KEY_LENGTH);
            memcpy(output + KEY_LENGTH, saplingKeys->nsk, KEY_LENGTH);
            break;

        default:
            return zxerr_invalid_crypto_settings;
    }
    return zxerr_ok;
}

zxerr_t crypto_computeSaplingSeed(uint8_t *sk) {
    if (sk == NULL) {
        return zxerr_no_data;
    }

    uint8_t privateKeyData[2*KEY_LENGTH] = {0};
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     NULL, NULL, 0));
    memcpy(sk, privateKeyData, KEY_LENGTH);

catch_cx_error:
    MEMZERO(privateKeyData, sizeof(privateKeyData));
    return zxerr_ok;
}

zxerr_t crypto_generateSaplingKeys(uint8_t *output, uint16_t outputLen, key_kind_e requestedKey) {
    if (output == NULL || outputLen < 3 * KEY_LENGTH) {
        return zxerr_buffer_too_small;
    }

    zxerr_t error = zxerr_unknown;
    MEMZERO(output, outputLen);

    keys_t saplingKeys = {0};
    uint8_t sk[KEY_LENGTH] = {0};
    CHECK_ZXERR(crypto_computeSaplingSeed(sk))
    CHECK_PARSER_OK(computeMasterFromSeed(sk, saplingKeys.spendingKey));

    error = computeKeys(&saplingKeys);

    // Copy keys
    if (error == zxerr_ok) {
        error = copyKeys(&saplingKeys, requestedKey, output, outputLen);
    } else {
    MEMZERO(sk, sizeof(sk));
    MEMZERO(&saplingKeys, sizeof(saplingKeys));
    }

    return error;
}

zxerr_t crypto_fillMASP(uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen, key_kind_e requestedKey) {
    if (buffer == NULL || cmdResponseLen == NULL) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    CHECK_ZXERR(crypto_generateSaplingKeys(buffer, bufferLen, requestedKey));
    switch (requestedKey) {
        case PublicAddress:
            *cmdResponseLen = KEY_LENGTH;
            break;

        case ViewKeys:
            *cmdResponseLen = 4 * KEY_LENGTH;
            break;

        case ProofGenerationKey:
            *cmdResponseLen = 2 * KEY_LENGTH;
            break;

        default:
            return zxerr_out_of_bounds;
    }

    return zxerr_ok;
}

static parser_error_t h_star(uint8_t *a, uint16_t a_len, uint8_t *b, uint16_t b_len, uint8_t *output) {
    if (a == NULL || b == NULL || output == NULL) {
        return parser_no_data;
    }

    uint8_t hash[BLAKE2B_OUTPUT_LEN] = {0};
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)SINGNING_REGJUBJUB,
                                           sizeof(SINGNING_REGJUBJUB)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, a, a_len));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, b, b_len));
    cx_blake2b_final(&ctx, hash);
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t *)SINGNING_REGJUBJUB,
                                      sizeof(SINGNING_REGJUBJUB));
    blake2b_update(&state, a, a_len);
    blake2b_update(&state, b, b_len);
    blake2b_final(&state, hash, BLAKE2B_OUTPUT_LEN);
#endif

    from_bytes_wide(hash, output);

    return parser_ok;
}
static zxerr_t sign_sapling_spend(keys_t *keys, uint8_t *alpha, uint8_t *sign_hash ,uint8_t *signature) {
    if (alpha == NULL || sign_hash == NULL || signature == NULL) {
        return zxerr_no_data;
    }

    uint8_t data_to_be_signed[2 * HASH_LEN] = {0};
    uint8_t rsk[KEY_LENGTH] = {0};
    uint8_t rk[KEY_LENGTH] = {0};

    // get randomized secret
    randomized_secret_from_seed(keys->ask, alpha, rsk);

    //rsk to rk
    scalar_multiplication(rsk, SpendingKeyGenerator, rk);

    // sign
    MEMCPY(data_to_be_signed, rk, KEY_LENGTH);
    MEMCPY(data_to_be_signed + KEY_LENGTH, sign_hash, HASH_LEN);

    // Get rng
    uint8_t rng[RNG_LEN] = {0};
    cx_rng_no_throw(rng, RNG_LEN);

    // Compute r and rbar
    uint8_t r[32] = {0};
    uint8_t rbar[32] = {0};
    CHECK_PARSER_OK(h_star(rng, sizeof(rng), data_to_be_signed, sizeof(data_to_be_signed), r));
    CHECK_PARSER_OK(scalar_multiplication(r, SpendingKeyGenerator, rbar));

    //compute s and sbar
    uint8_t s[32] = {0};
    uint8_t sbar[32] = {0};
    CHECK_PARSER_OK(h_star(rbar, sizeof(rbar), data_to_be_signed, sizeof(data_to_be_signed), s));
    CHECK_PARSER_OK(compute_sbar(s, r, rsk, sbar));

    MEMCPY(signature, rbar, HASH_LEN);
    MEMCPY(signature + HASH_LEN, sbar, HASH_LEN);

    return zxerr_ok;
}
zxerr_t crypto_sign_spends_sapling(const parser_tx_t *txObj, uint8_t *output, uint16_t outputLen, uint16_t *responseLen) {
    zemu_log_stack("crypto_signspends_sapling");
    if (txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends == 0) {
        return zxerr_ok;
    }

    MEMZERO(output, outputLen);
    // Get Signature hash
    uint8_t sign_hash[HASH_LEN] = {0};
    signature_hash(txObj, sign_hash);

    // Get keys to use ask
    uint8_t sapling_seed[KEY_LENGTH] = {0};
    keys_t keys = {0};
    CHECK_ZXERR(crypto_computeSaplingSeed(sapling_seed));
    CHECK_PARSER_OK(computeMasterFromSeed(sapling_seed, keys.spendingKey));
    CHECK_ZXERR(computeKeys(&keys));

    uint8_t signature[2 * HASH_LEN] = {0};
    uint8_t alpha[KEY_LENGTH] = {0};
    const uint8_t *spend = txObj->transaction.sections.maspBuilder.builder.sapling_builder.spends.ptr;
    uint16_t spendLen = 0;

    for (uint64_t i = 0; i < txObj->transaction.sections.maspBuilder.builder.sapling_builder.n_spends; i++) {
        // Get spend description and alpha
        spend += spendLen;
        MEMCPY(alpha, spend + ALPHA_OFFSET, KEY_LENGTH);

        CHECK_ZXERR(sign_sapling_spend(&keys, alpha, sign_hash, signature));

        // Copy signature to output
        MEMCPY(output + i * MASP_SIG_LEN, signature, MASP_SIG_LEN);

        // Get this spend lenght to get next one
        getSpendDescriptionLen(spend, &spendLen);

        *responseLen += MASP_SIG_LEN;
    }

    return zxerr_ok;
}

zxerr_t crypto_sign_masp(const parser_tx_t *txObj, uint8_t *output, uint16_t outputLen, uint16_t *responseLen) {
    if (txObj == NULL || output == NULL || outputLen < 2 * ED25519_SIGNATURE_SIZE) {
        return zxerr_unknown;
    }

    // Sign Sapling spends
    CHECK_ZXERR(crypto_sign_spends_sapling(txObj, output, outputLen, responseLen));

    return zxerr_ok;
}

static zxerr_t random_fr(uint8_t *buffer, uint16_t bufferLen) {
    if (buffer == NULL || bufferLen < 32) {
        return zxerr_unknown;
    }

    uint8_t rnd_data[64] = {0};
    cx_trng_get_random_data(rnd_data, 64);
    CHECK_PARSER_OK(from_bytes_wide(rnd_data, buffer));

    return zxerr_ok;
}

zxerr_t crypto_computeRandomness(const uint8_t *buffer, uint16_t bufferLen, uint8_t *out, uint16_t outLen, uint16_t *replyLen) {
    if(buffer == NULL || bufferLen != 3 || out == NULL ||replyLen == NULL) {
        return zxerr_unknown;
    }
    MEMZERO(out, outLen);
    zemu_log_stack("crypto_computeRandomness");
    uint8_t spend_len = buffer[0];
    uint8_t output_len = buffer[1];
    uint8_t convert_len = buffer[2];
    uint8_t tmp_rnd[32] = {0};

    zemu_log_stack("crypto_computeRandomness");
    transaction_add_sizes(spend_len, output_len, convert_len);

    ZEMU_LOGF(50,"spend_len: %d, output_len: %d, convert_len: %d\n", spend_len, output_len, convert_len);
    //value commitment randomness + spend auth randomizer
    for (uint8_t i = 0; i < 2 * spend_len; i++) {
        CHECK_ZXERR(random_fr(tmp_rnd, RANDOM_LEN));
        MEMCPY(out + (i * RANDOM_LEN), tmp_rnd, RANDOM_LEN);
    }   

    //value commitment randomness + random seed
    for (uint8_t i = 0; i < 2 * output_len; i++) {
        if (i % 2 == 0) {
            CHECK_ZXERR(random_fr(tmp_rnd, RANDOM_LEN));
        } else {
            cx_rng(tmp_rnd, RANDOM_LEN);
        }
        MEMCPY(out + (2 * spend_len * RANDOM_LEN) + (i * RANDOM_LEN), tmp_rnd, RANDOM_LEN);
    }

    //value commitment randomness
    for (uint8_t i = 0; i < convert_len; i++) {
        CHECK_ZXERR(random_fr(tmp_rnd, RANDOM_LEN));
        MEMCPY(out +(2 * spend_len * RANDOM_LEN) + (2 * output_len * RANDOM_LEN) + (i * RANDOM_LEN), tmp_rnd, RANDOM_LEN);
    }

    *replyLen = (2 * spend_len * RANDOM_LEN) * (2 + output_len * RANDOM_LEN) + (convert_len * RANDOM_LEN);
    return zxerr_ok;
}
