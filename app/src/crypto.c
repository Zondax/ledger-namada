/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    #include "cx.h"
    #include "cx_sha256.h"
    #include "cx_blake2b.h"
#else
    #include "picohash.h"
    #include "blake2.h"
    #define CX_SHA256_SIZE 32
#endif
#include "blake2.h"

#define DISCRIMINANT_HEADER 0x06
#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE (SIGN_PREFIX_SIZE + CX_SHA256_SIZE)

#define MAX_SIGNATURE_HASHES 10

#define CHECK_PARSER_OK(CALL)      \
  do {                         \
    parser_error_t __cx_err = CALL;  \
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
    const uint8_t discriminant = DISCRIMINANT_HEADER;
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
    const uint8_t discriminant = DISCRIMINANT_HEADER;
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
           if (txObj->updateVp.has_vp_code) {
                MEMCPY(hashes->hashes.ptr + hashes->hashesLen * HASH_LEN, txObj->updateVp.vp_type_sechash.ptr, HASH_LEN);
                hashes->indices.ptr[hashes->hashesLen] = txObj->updateVp.vp_type_secidx;
                hashes->hashesLen++;
            }
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

zxerr_t crypto_hashMaspSection(const uint8_t *input, uint64_t inputLen, uint8_t* output) {
    if (input == NULL || output == NULL) {
        return zxerr_invalid_crypto_settings;
    }
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, input, (size_t)inputLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
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

    // Hashes: code, data, (initAcc | initVali | updateVP = 1  /  initProp = 2), raw_signature, header, masp ---> MaxHashes = 6
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

    // Include Masp hash in the signature if it's there
    if (txObj->transaction.isMasp) {
#if !defined(APP_TESTING)
        if (get_state() != STATE_EXTRACT_SPENDS) {
            return zxerr_unknown;
        }
#endif
        const uint8_t *maspSection = txObj->transaction.sections.maspTx.masptx_ptr;
        uint64_t maspSectionLen = txObj->transaction.sections.maspTx.masptx_len;
        uint8_t *maspHash = section_hashes.hashes.ptr + (section_hashes.hashesLen * HASH_LEN);
        CHECK_ZXERR(crypto_hashMaspSection(maspSection, maspSectionLen, maspHash))
        section_hashes.indices.ptr[section_hashes.hashesLen] = txObj->transaction.maspTx_idx;
        section_hashes.hashesLen++;
        signature_section.hashes.hashesLen++;
    } 

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
            if (outputLen < 5 * KEY_LENGTH) {
                return zxerr_buffer_too_small;
            }
            memcpy(output, saplingKeys->ak, KEY_LENGTH);
            memcpy(output + KEY_LENGTH, saplingKeys->nk, KEY_LENGTH);
            memcpy(output + 2 * KEY_LENGTH, saplingKeys->ovk, KEY_LENGTH);
            memcpy(output + 3 * KEY_LENGTH, saplingKeys->ivk, KEY_LENGTH);
            memcpy(output + 4 * KEY_LENGTH, saplingKeys->dk, KEY_LENGTH);
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

zxerr_t crypto_computeSaplingSeed(uint8_t spendingKey[static KEY_LENGTH]) {
    if (spendingKey == NULL ) {
        return zxerr_no_data;
    }
    zxerr_t error = zxerr_unknown;
    uint8_t privateKeyData[2*KEY_LENGTH] = {0};
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     NULL, NULL, 0));
    memcpy(spendingKey, privateKeyData, KEY_LENGTH);
    error = zxerr_ok;

catch_cx_error: 
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if(error != zxerr_ok) {
        MEMZERO(spendingKey, KEY_LENGTH);
    }

    return error;
}

zxerr_t crypto_generateSaplingKeys(uint8_t *output, uint16_t outputLen, key_kind_e requestedKey) {
    if (output == NULL || outputLen < 3 * KEY_LENGTH) {
        return zxerr_buffer_too_small;
    }

    zxerr_t error = zxerr_unknown;
    MEMZERO(output, outputLen);

    keys_t saplingKeys = {0};
    uint8_t sk[KEY_LENGTH] = {0};

    // sk erased inside in case of error
    CHECK_ZXERR(crypto_computeSaplingSeed(sk))

    if (computeMasterFromSeed((const uint8_t*) sk, saplingKeys.spendingKey) != parser_ok) {
        MEMZERO(sk, sizeof(sk));
        return zxerr_unknown;
    }

    error = computeKeys(&saplingKeys);

    // Copy keys
    if (error == zxerr_ok) {
        error = copyKeys(&saplingKeys, requestedKey, output, outputLen);
    }

    MEMZERO(sk, sizeof(sk));
    MEMZERO(&saplingKeys, sizeof(saplingKeys));
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
            *cmdResponseLen = 5 * KEY_LENGTH;
            break;

        case ProofGenerationKey:
            *cmdResponseLen = 2 * KEY_LENGTH;
            break;

        default:
            return zxerr_out_of_bounds;
    }

    return zxerr_ok;
}

// https://github.com/anoma/masp/blob/8d83b172698098fba393006016072bc201ed9ab7/masp_primitives/src/sapling.rs#L170
// https://github.com/anoma/masp/blob/main/masp_primitives/src/sapling/redjubjub.rs#L136
static zxerr_t sign_sapling_spend(keys_t *keys, uint8_t alpha[static KEY_LENGTH], uint8_t sign_hash[static KEY_LENGTH], uint8_t *signature) {
    if (alpha == NULL || sign_hash == NULL || signature == NULL) {
        return zxerr_no_data;
    }

    uint8_t data_to_be_signed[2 * HASH_LEN] = {0};
    uint8_t rsk[KEY_LENGTH] = {0};
    uint8_t rk[KEY_LENGTH] = {0};

    // get randomized secret
    CHECK_PARSER_OK(parser_randomized_secret_from_seed(keys->ask, alpha, rsk));

    //rsk to rk
    CHECK_PARSER_OK(parser_scalar_multiplication(rsk, SpendingKeyGenerator, rk));

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
    CHECK_PARSER_OK(parser_scalar_multiplication(r, SpendingKeyGenerator, rbar));

    //compute s and sbar
    uint8_t s[32] = {0};
    uint8_t sbar[32] = {0};
    CHECK_PARSER_OK(h_star(rbar, sizeof(rbar), data_to_be_signed, sizeof(data_to_be_signed), s));
    CHECK_PARSER_OK(parser_compute_sbar(s, r, rsk, sbar));

    MEMCPY(signature, rbar, HASH_LEN);
    MEMCPY(signature + HASH_LEN, sbar, HASH_LEN);

    return zxerr_ok;
}

zxerr_t crypto_sign_spends_sapling(const parser_tx_t *txObj, keys_t *keys) {
    zemu_log_stack("crypto_signspends_sapling");
    if (txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends == 0) {
        return zxerr_ok;
    }

    // Get Signature hash
    uint8_t sign_hash[HASH_LEN] = {0};
    signature_hash(txObj, sign_hash);

    uint8_t signature[2 * HASH_LEN] = {0};
    const uint8_t *spend = txObj->transaction.sections.maspBuilder.builder.sapling_builder.spends.ptr;
    uint16_t spendLen = 0;

    for (uint64_t i = 0; i < txObj->transaction.sections.maspBuilder.builder.sapling_builder.n_spends; i++) {
        // Get spend description and alpha
        spend += spendLen;
        spend_item_t *item = spendlist_retrieve_rand_item(i);

        CHECK_ZXERR(sign_sapling_spend(keys, item->alpha, sign_hash, signature));

        // Save signature in flash
        CHECK_ZXERR(spend_signatures_append(signature));

        // Get this spend lenght to get next one
        getSpendDescriptionLen(spend, &spendLen);
    }

    return zxerr_ok;
}

zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen) {
    if (!spend_signatures_more_extract() || (get_state() != STATE_SIGNED_SPENDS && get_state() != STATE_EXTRACT_SPENDS)) {
        zemu_log_stack("crypto_extract_spend_signature: no more signatures");
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    *cmdResponseLen = SIGNATURE_SIZE;
    return get_next_spend_signature(buffer);
}

parser_error_t checkSpends(const parser_tx_t *txObj, keys_t *keys, parser_context_t *builder_spends_ctx, parser_context_t *tx_spends_ctx, parser_context_t *indices_ctx) {
    if (txObj == NULL || keys == NULL) {
        return parser_unexpected_error;
    }

    if (txObj->transaction.sections.maspBuilder.metadata.n_spends_indices != txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends) {
        return parser_invalid_number_of_spends;
    }

    for (uint64_t indice = 0; indice < txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends; indice++) {
        // Find the spend descriptor information object corresponding to this
        // spend descriptor
        uint32_t i;
        for (i = 0; i < txObj->transaction.sections.maspBuilder.metadata.n_spends_indices; i++) {
            uint64_t curr_indice;
            CHECK_ERROR(readUint64(indices_ctx, &curr_indice));
            if (curr_indice == indice) break;
        }

        CTX_CHECK_AND_ADVANCE(tx_spends_ctx, SHIELDED_SPENDS_LEN * indice);
        spend_item_t *item = spendlist_retrieve_rand_item(indice);

        if(i > txObj->transaction.sections.maspBuilder.metadata.n_spends_indices) {
            return parser_invalid_number_of_spends;
        } 
        
        CHECK_ERROR(getNextSpendDescription(builder_spends_ctx, i));

        //check cv computation validaded in cpp_tests
        uint8_t cv[KEY_LENGTH] = {0};
        uint8_t identifier[IDENTIFIER_LEN] = {0};
        uint64_t value = 0;
        CTX_CHECK_AND_ADVANCE(builder_spends_ctx, EXTENDED_FVK_LEN + DIVERSIFIER_LEN)
        CHECK_ERROR(readBytesSize(builder_spends_ctx, identifier, IDENTIFIER_LEN));
        CHECK_ERROR(readUint64(builder_spends_ctx, &value));

        CHECK_ERROR(computeValueCommitment(value, item->rcv, identifier, cv));
        if(MEMCMP(cv, tx_spends_ctx->buffer + tx_spends_ctx->offset, CV_LEN) != 0) {
            return parser_invalid_cv;
        }

        //check rk
        uint8_t rk[KEY_LENGTH] = {0};
        CHECK_ERROR(computeRk(keys, item->alpha, rk));

        CTX_CHECK_AND_ADVANCE(tx_spends_ctx, CV_LEN + NULLIFIER_LEN);
#ifndef APP_TESTING
        if (MEMCMP(rk, tx_spends_ctx->buffer + tx_spends_ctx->offset, RK_LEN) != 0) {
            return parser_invalid_rk;
        }
#endif

        builder_spends_ctx->offset = 0;
        tx_spends_ctx->offset = 0;
    }
    return parser_ok;
}

parser_error_t checkOutputs(const parser_tx_t *txObj, parser_context_t *builder_outputs_ctx, parser_context_t *tx_outputs_ctx, parser_context_t *indices_ctx) {
    if (txObj == NULL) {
        return parser_unexpected_error;
    }

    if (txObj->transaction.sections.maspBuilder.metadata.n_outputs_indices != txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_outputs) {
        return parser_invalid_number_of_outputs;
    }

    for (uint64_t indice = 0; indice < txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_outputs; indice++) {
        // Find the output descriptor information object corresponding to this
        // output descriptor
        uint32_t i;
        for (i = 0; i < txObj->transaction.sections.maspBuilder.metadata.n_outputs_indices; i++) {
            uint64_t curr_indice;
            CHECK_ERROR(readUint64(indices_ctx, &curr_indice));
            if (curr_indice == indice) break;
        }
        CTX_CHECK_AND_ADVANCE(tx_outputs_ctx, SHIELDED_OUTPUTS_LEN * indice);
        output_item_t *item = outputlist_retrieve_rand_item(indice);
        uint64_t value = 0;
        // Use the dummy note identifier as the default
        uint8_t identifier[IDENTIFIER_LEN] = DEFAULT_IDENTIFIER;

        if (i > txObj->transaction.sections.maspBuilder.metadata.n_outputs_indices) {
            return parser_invalid_number_of_outputs;
        }
        
        CHECK_ERROR(getNextOutputDescription(builder_outputs_ctx, i));
        uint8_t has_ovk = 0;
        CHECK_ERROR(readByte(builder_outputs_ctx, &has_ovk));
        CTX_CHECK_AND_ADVANCE(builder_outputs_ctx, (has_ovk ? 32 : 0) + DIVERSIFIER_LEN + PAYMENT_ADDR_LEN);
        CHECK_ERROR(readBytesSize(builder_outputs_ctx, identifier, IDENTIFIER_LEN));
        CHECK_ERROR(readUint64(builder_outputs_ctx, &value));

        //check cv computation validaded in cpp_tests
        uint8_t cv[KEY_LENGTH] = {0};
        CHECK_ERROR(computeValueCommitment(value, item->rcv, identifier, cv));
        if(MEMCMP(cv, tx_outputs_ctx->buffer + tx_outputs_ctx->offset, CV_LEN) != 0) {
            return parser_invalid_cv;
        }

        builder_outputs_ctx->offset = 0;
        tx_outputs_ctx->offset = 0;
        indices_ctx->offset = 0;
    }
    return parser_ok;
}

parser_error_t checkConverts(const parser_tx_t *txObj, parser_context_t *builder_converts_ctx, parser_context_t *tx_converts_ctx, parser_context_t *indices_ctx) {
    if (txObj == NULL) {
        return parser_unexpected_error;
    }

    if (txObj->transaction.sections.maspBuilder.metadata.n_converts_indices != txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_converts) {
        return parser_invalid_number_of_converts;
    }

    for (uint32_t i = 0; i < txObj->transaction.sections.maspBuilder.builder.sapling_builder.n_converts; i++) {
        CHECK_ERROR(getNextConvertDescription(builder_converts_ctx, i));

        uint64_t indice = 0;
        CHECK_ERROR(readUint64(indices_ctx, &indice));
        CTX_CHECK_AND_ADVANCE(tx_converts_ctx, SHIELDED_CONVERTS_LEN * indice);
        convert_item_t *item = convertlist_retrieve_rand_item(indice);

        //check cv (computation validaded in cpp_tests
        uint8_t cv[KEY_LENGTH] = {0};
        uint8_t generator[IDENTIFIER_LEN] = {0};
        uint64_t value = 0;

        uint64_t tmp_64 = 0;
        CHECK_ERROR(readCompactSize(builder_converts_ctx, &tmp_64));
        uint16_t len = tmp_64 * (ASSET_ID_LEN + INT_128_LEN);
        CTX_CHECK_AND_ADVANCE(builder_converts_ctx, len);
        CHECK_ERROR(readBytesSize(builder_converts_ctx, generator, IDENTIFIER_LEN));
        CHECK_ERROR(readUint64(builder_converts_ctx, &value));

        CHECK_ERROR(computeConvertValueCommitment(value, item->rcv, generator, cv));
        if(MEMCMP(cv, tx_converts_ctx->buffer + tx_converts_ctx->offset, CV_LEN) != 0) {
            return parser_invalid_cv;
        }

        builder_converts_ctx->offset = 0;
        tx_converts_ctx->offset = 0;
    }
    return parser_ok;
}

zxerr_t crypto_check_masp(const parser_tx_t *txObj, keys_t *keys) {
    if (txObj == NULL || keys == NULL) {
        return zxerr_unknown;
    }

    // For now verify cv and rk https://github.com/anoma/masp/blob/main/masp_proofs/src/sapling/prover.rs#L278    
    // Check Spends
    parser_context_t builder_spends_ctx =  {.buffer = txObj->transaction.sections.maspBuilder.builder.sapling_builder.spends.ptr,
                                            .bufferLen = txObj->transaction.sections.maspBuilder.builder.sapling_builder.spends.len,
                                            .offset = 0, 
                                            .tx_obj = NULL};
    parser_context_t tx_spends_ctx = {.buffer = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_spends.ptr,
                                      .bufferLen = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_spends.len,
                                      .offset = 0, 
                                      .tx_obj = NULL};
    parser_context_t spends_indices_ctx = {.buffer = txObj->transaction.sections.maspBuilder.metadata.spends_indices.ptr,
                                        .bufferLen = txObj->transaction.sections.maspBuilder.metadata.spends_indices.len,
                                        .offset = 0, 
                                        .tx_obj = NULL};
    CHECK_PARSER_OK(checkSpends(txObj, keys, &builder_spends_ctx, &tx_spends_ctx, &spends_indices_ctx));

    // Check outputs
    parser_context_t builder_outputs_ctx = {.buffer = txObj->transaction.sections.maspBuilder.builder.sapling_builder.outputs.ptr,
                                           .bufferLen = txObj->transaction.sections.maspBuilder.builder.sapling_builder.outputs.len,
                                           .offset = 0, 
                                           .tx_obj = NULL};
    parser_context_t tx_outputs_ctx = {.buffer = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_outputs.ptr,
                                     .bufferLen = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_outputs.len,
                                     .offset = 0, 
                                     .tx_obj = NULL};
    parser_context_t output_indices_ctx = {.buffer = txObj->transaction.sections.maspBuilder.metadata.outputs_indices.ptr,
                                .bufferLen = txObj->transaction.sections.maspBuilder.metadata.outputs_indices.len,
                                .offset = 0, 
                                .tx_obj = NULL};
    CHECK_PARSER_OK(checkOutputs(txObj, &builder_outputs_ctx, &tx_outputs_ctx, &output_indices_ctx));

    // Check converts
    parser_context_t builder_converts_ctx = {.buffer = txObj->transaction.sections.maspBuilder.builder.sapling_builder.converts.ptr,
                                           .bufferLen = txObj->transaction.sections.maspBuilder.builder.sapling_builder.converts.len,
                                           .offset = 0, 
                                           .tx_obj = NULL};
    parser_context_t tx_converts_ctx = {.buffer = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_converts.ptr,
                                        .bufferLen = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_converts.len,
                                        .offset = 0, 
                                        .tx_obj = NULL};
    parser_context_t converts_indices_ctx = {.buffer = txObj->transaction.sections.maspBuilder.metadata.converts_indices.ptr,
                                           .bufferLen = txObj->transaction.sections.maspBuilder.metadata.converts_indices.len,
                                           .offset = 0, 
                                           .tx_obj = NULL};
    CHECK_PARSER_OK(checkConverts(txObj, &builder_converts_ctx, &tx_converts_ctx, &converts_indices_ctx));
    return zxerr_ok;
}

zxerr_t crypto_hash_messagebuffer(uint8_t *buffer, uint16_t bufferLen,
                                  const uint8_t *txdata, uint16_t txdataLen) {
  if (bufferLen < CX_SHA256_SIZE) {
    return zxerr_unknown;
  }
  cx_hash_sha256(txdata, txdataLen, buffer, CX_SHA256_SIZE);  // SHA256
  return zxerr_ok;
}

zxerr_t crypto_sign_masp_spends(parser_tx_t *txObj, uint8_t *output, uint16_t outputLen) {
    if (txObj == NULL || output == NULL || outputLen < ED25519_SIGNATURE_SIZE) {
        return zxerr_unknown;
    }

    if (get_state() != STATE_PROCESSED_RANDOMNESS) {
        return zxerr_unknown;
    }

    // Get keys
    uint8_t sapling_seed[KEY_LENGTH] = {0};
    keys_t keys = {0};
    CHECK_ZXERR(crypto_computeSaplingSeed(sapling_seed));
    if (computeMasterFromSeed(sapling_seed, keys.spendingKey)) {
        MEMZERO(sapling_seed, sizeof(sapling_seed));
        return zxerr_unknown;
    }

    if (computeKeys(&keys) != zxerr_ok || crypto_check_masp(txObj, &keys) != zxerr_ok || 
        crypto_sign_spends_sapling(txObj, &keys) != zxerr_ok) {
        MEMZERO(sapling_seed, sizeof(sapling_seed));
        MEMZERO(&keys, sizeof(keys));
        return zxerr_invalid_crypto_settings;
    }

    //Hash buffer and retreive for verify purpose
    zxerr_t err = crypto_hash_messagebuffer(output, outputLen, tx_get_buffer(), tx_get_buffer_length());

    MEMZERO(sapling_seed, sizeof(sapling_seed));
    MEMZERO(&keys, sizeof(keys));

    if (err == zxerr_ok) {
        set_state(STATE_SIGNED_SPENDS);
    }

    return err;
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

zxerr_t crypto_computeRandomness(masp_type_e type, uint8_t *out, uint16_t outLen, uint16_t *replyLen) {
    if(out == NULL ||replyLen == NULL || outLen < (2 * RANDOM_LEN)) {
        return zxerr_unknown;
    }
    MEMZERO(out, outLen);

#ifdef APP_TESTING
    uint8_t out_tmp_rnd[RANDOM_LEN] = {0xb1, 0x85, 0x95, 0x9d, 0xdb, 0x84, 0x1a, 0x7f, 0x97, 0x40,
                                       0x9b, 0x22, 0xec, 0x0e, 0xf8, 0x52, 0xce, 0x98, 0xc9, 0x6a,
                                       0xf0, 0xa0, 0x62, 0xa4, 0xdc, 0xff, 0x0a, 0xe7, 0x77, 0x10,
                                       0xf0, 0x0c};

    uint8_t out_tmp_rnd2[RANDOM_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00};

    uint8_t out1_tmp_rnd[RANDOM_LEN] = {0x9c, 0xf4, 0x3f, 0x46, 0xb1, 0xa6, 0x1d, 0xae, 0xf8, 0x41,
                                        0x32, 0xdb, 0xca, 0xe7, 0xea, 0x88, 0xa3, 0xe1, 0x2c, 0x66,
                                        0xe0, 0x71, 0x05, 0x47, 0xc9, 0x6d, 0x84, 0xf3, 0xc4, 0x24,
                                        0xa0, 0x0d};

    uint8_t out1_tmp_rnd2[RANDOM_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00};

    uint8_t spend_tmp_rnd[RANDOM_LEN] = {0x22, 0xc9, 0x0b, 0xa7, 0x43, 0x91, 0x6e, 0x04, 0xd2, 0xfe,
                                         0xea, 0x70, 0x7a, 0xbb, 0xac, 0x40, 0xdb, 0x36, 0x05, 0xa8,
                                         0x7c, 0xa6, 0x71, 0xab, 0x23, 0xda, 0xc3, 0x01, 0x72, 0xbb,
                                         0x03, 0x0d};
    
    uint8_t spend_tmp_rnd2[RANDOM_LEN] = {0xc8, 0x06, 0x96, 0x04, 0x94, 0xf8, 0x5d, 0x02, 0x13, 0x61,
                                          0xcb, 0x07, 0x97, 0x8d, 0x6e, 0x71, 0xec, 0xa5, 0xc0, 0xbf,
                                          0xe4, 0xc8, 0xe9, 0x3d, 0x0a, 0x10, 0x85, 0x74, 0xe5, 0x04,
                                          0x94, 0x06};

    uint8_t convert_tmp_rnd[RANDOM_LEN] = {0x22, 0xf4, 0x88, 0x3d, 0xdc, 0x2d, 0x8e, 0x47, 0xbd, 0xfc,
                                           0xb3, 0xb5, 0x44, 0x2c, 0x04, 0x1c, 0xa5, 0xeb, 0x1d, 0x97,
                                           0x76, 0xea, 0x1c, 0xcd, 0xef, 0x05, 0x1b, 0xd0, 0xce, 0x30,
                                           0xd8, 0x03};

    uint8_t convert_tmp_rnd2[RANDOM_LEN] = {0x03, 0xd8, 0x30, 0xce, 0xd0, 0x1b, 0x05, 0xef, 0xcd, 0x1c,
                                           0xea, 0x76, 0x97, 0x1d, 0xeb, 0xa5, 0x1c, 0x04, 0x2c, 0x44,
                                           0xb5, 0xb3, 0xfc, 0xbd, 0x47, 0x8e, 0x2d, 0xdc, 0x3d, 0x88,
                                           0xf4, 0x22};
#else 
    uint8_t tmp_rnd[RANDOM_LEN] = {0};
    uint8_t tmp_rnd2[RANDOM_LEN] = {0};
#endif

    switch(type){
        case spend:
#ifdef APP_TESTING
            MEMCPY(out, spend_tmp_rnd, RANDOM_LEN);
            MEMCPY(out + RANDOM_LEN, spend_tmp_rnd2, RANDOM_LEN);
            CHECK_ZXERR(spend_append_rand_item(spend_tmp_rnd, spend_tmp_rnd2));
#else
            CHECK_ZXERR(random_fr(tmp_rnd, RANDOM_LEN));
            MEMCPY(out, tmp_rnd, RANDOM_LEN);
            CHECK_ZXERR(random_fr(tmp_rnd2, RANDOM_LEN));
            MEMCPY(out + RANDOM_LEN, tmp_rnd2, RANDOM_LEN);

            CHECK_ZXERR(spend_append_rand_item(tmp_rnd, tmp_rnd2));
#endif
            *replyLen = 2 * RANDOM_LEN;
            break;
        case output:
#ifdef APP_TESTING
            MEMCPY(out, out_tmp_rnd, RANDOM_LEN);
            MEMCPY(out + RANDOM_LEN, out_tmp_rnd2, RANDOM_LEN);
            CHECK_ZXERR(output_append_rand_item(out_tmp_rnd, out_tmp_rnd2));
            CHECK_ZXERR(output_append_rand_item(out1_tmp_rnd, out1_tmp_rnd2));
#else
            CHECK_ZXERR(random_fr(tmp_rnd, RANDOM_LEN));
            MEMCPY(out, tmp_rnd, RANDOM_LEN);
            cx_rng(tmp_rnd2, RANDOM_LEN);
            MEMCPY(out + RANDOM_LEN, tmp_rnd2, RANDOM_LEN);

            CHECK_ZXERR(output_append_rand_item(tmp_rnd, tmp_rnd2));
#endif
            *replyLen = 2 * RANDOM_LEN;
            break;
        case convert:
#ifdef APP_TESTING
            MEMCPY(out, convert_tmp_rnd, RANDOM_LEN);
            CHECK_ZXERR(convert_append_rand_item(convert_tmp_rnd));
            CHECK_ZXERR(convert_append_rand_item(convert_tmp_rnd2));
#else
            CHECK_ZXERR(random_fr(tmp_rnd, RANDOM_LEN));
            MEMCPY(out, tmp_rnd, RANDOM_LEN);

            CHECK_ZXERR(convert_append_rand_item(tmp_rnd));
#endif
            *replyLen = RANDOM_LEN;
            break;
        default:
            return zxerr_unknown;
    }
    return zxerr_ok;
}
