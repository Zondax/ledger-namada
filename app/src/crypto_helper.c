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
#include "crypto_helper.h"
#include "coin.h"
#include "bech32.h"
#include "zxformat.h"
#include "leb128.h"
#include "zxmacros.h"
#include "bech32_encoding.h"
#include "parser_address.h"

#include "keys_personalizations.h"
#include "rslib.h"

#ifdef LEDGER_SPECIFIC
#include "bolos_target.h"
#endif

#define MAINNET_ADDRESS_T_HRP "tnam"
#define MAINNET_PUBKEY_T_HRP "tpknam"

#define TESTNET_ADDRESS_T_HRP "testtnam"
#define TESTNET_PUBKEY_T_HRP "testtpknam"

#define MAINNET_EXT_FULL_VIEWING_KEY_HRP "zvknam"
#define MAINNET_PAYMENT_ADDR_HRP "znam"
#define TESTNET_EXT_FULL_VIEWING_KEY_HRP "testzvknam"
#define TESTNET_PAYMENT_ADDR_HRP "testznam"

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

uint32_t hdPath[HDPATH_LEN_DEFAULT];

uint8_t bech32_hrp_len;
char bech32_hrp[MAX_BECH32_HRP_LEN + 1];

static zxerr_t crypto_publicKeyHash_ed25519(uint8_t *publicKeyHash, const uint8_t *pubkey){
    if (publicKeyHash == NULL || pubkey == NULL) {
        return zxerr_no_data;
    }

    // Step 1.  First borsh serialize pubkey (this prepends a 0 to the bytes of pubkey);
    uint8_t borshEncodedPubKey[PK_LEN_25519 + 1] = {0};
    memcpy(borshEncodedPubKey + 1, pubkey, PK_LEN_25519);

    // Step 2. Hash the serialized public key with sha256.
    uint8_t pkh[CX_SHA256_SIZE] = {0};
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_hash_sha256((const uint8_t*) borshEncodedPubKey, PK_LEN_25519 + 1, pkh, CX_SHA256_SIZE);
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, borshEncodedPubKey, PK_LEN_25519 + 1);
    picohash_final(&ctx, pkh);
#endif
    CHECK_APP_CANARY()

    // Step 3. Take the hex encoding of the hash (using upper-case);
    char hexPubKeyHash[2 * CX_SHA256_SIZE + 1] = {0};
    array_to_hexstr_uppercase(hexPubKeyHash, 2 * CX_SHA256_SIZE + 1, pkh, CX_SHA256_SIZE);

    // Prepend implicit address prefix
    publicKeyHash[0] = 0;

    // Step 4. The Public Key Hash consists of the first 40 characters of the hex encoding. ---> UPPERCASE
    MEMCPY(publicKeyHash + 1, pkh, PK_HASH_LEN);

    return zxerr_ok;
}

zxerr_t crypto_encodeRawPubkey(const uint8_t* rawPubkey, uint16_t rawPubkeyLen, uint8_t *output, uint16_t outputLen) {
    if (rawPubkey == NULL || rawPubkeyLen != PK_LEN_25519_PLUS_TAG || output == NULL) {
        return zxerr_encoding_failed;
    }
    MEMZERO(output, outputLen);
    // Response [len(1) | pubkey(?)]

    char HRP[15] = MAINNET_PUBKEY_T_HRP;
    if (hdPath[1] == HDPATH_1_TESTNET) {
        strcpy(HRP, TESTNET_PUBKEY_T_HRP);
    }

    char pubkey[100] = {0};
    CHECK_ZXERR(bech32EncodeFromBytes(pubkey, sizeof(pubkey), HRP,
                                      rawPubkey, PK_LEN_25519_PLUS_TAG, 1, BECH32_ENCODING_BECH32M));

    const uint16_t pubkeyLen = strnlen(pubkey, sizeof(pubkey));
    if (pubkeyLen > 255 || pubkeyLen >= outputLen) {
        return zxerr_out_of_bounds;
    }
    *output = (uint8_t)pubkeyLen;
    memcpy(output + 1, pubkey, pubkeyLen);
    return zxerr_ok;
}

zxerr_t crypto_encodeAddress(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *output, uint16_t outputLen) {
    if (output == NULL || pubkey == NULL || pubkeyLen != PK_LEN_25519) {
        return zxerr_encoding_failed;
    }

    // Step 1:  Compute the hash of the Ed25519 public key
    uint8_t publicKeyHash[21] = {0};
    CHECK_ZXERR(crypto_publicKeyHash_ed25519(publicKeyHash, pubkey));

    char HRP[10] = MAINNET_ADDRESS_T_HRP;
    if (hdPath[1] == HDPATH_1_TESTNET) {
        strcpy(HRP, TESTNET_ADDRESS_T_HRP);
    }

    // Step 2. Encode the public key hash with bech32m
    char address[100] = {0};
    CHECK_ZXERR(bech32EncodeFromBytes(address, sizeof(address), HRP,
                                      publicKeyHash, sizeof(publicKeyHash), 1, BECH32_ENCODING_BECH32M));

    const uint16_t addressLen = strnlen(address, sizeof(address));
    if (addressLen > 255 || addressLen >= outputLen) {
        return zxerr_out_of_bounds;
    }
    *output = (uint8_t)addressLen;
    memcpy(output + 1, address, addressLen);
    return zxerr_ok;
}

parser_error_t crypto_encodeLargeBech32(const uint8_t *address, size_t addressLen, uint8_t *output, size_t outputLen, bool paymentAddr) {
    if (output == NULL || address == NULL) {
        return parser_unexpected_value;
    }

    char HRP[12] = MAINNET_PAYMENT_ADDR_HRP;
    if (!paymentAddr) {
        strcpy(HRP, MAINNET_EXT_FULL_VIEWING_KEY_HRP);
    }

#if defined(LEDGER_SPECIFIC)
    if (hdPath[1] == HDPATH_1_TESTNET) {
        strcpy(HRP, TESTNET_PAYMENT_ADDR_HRP);
        if (!paymentAddr) {
            strcpy(HRP, TESTNET_EXT_FULL_VIEWING_KEY_HRP);
        }
    }
#endif

    if(bech32EncodeFromLargeBytes((char *)output, outputLen, HRP, (uint8_t*) address, addressLen, 1, BECH32_ENCODING_BECH32M) != zxerr_ok) {
        return parser_unexpected_value;
    };
    return parser_ok;
}

parser_error_t crypto_encodeAltAddress(const AddressAlt *addr, char *address, uint16_t addressLen) {
    uint8_t tmpBuffer[ADDRESS_LEN_BYTES] = {0};

    switch (addr->tag) {
        case 0:
            tmpBuffer[0] = PREFIX_ESTABLISHED;
            MEMCPY(tmpBuffer + 1, addr->Established.hash.ptr, 20);
            break;
        case 1:
            tmpBuffer[0] = PREFIX_IMPLICIT;
            MEMCPY(tmpBuffer + 1, addr->Implicit.pubKeyHash.ptr, 20);
            break;
        case 2:
            switch (addr->Internal.tag) {
            case 0:
              tmpBuffer[0] = PREFIX_POS;
              break;
            case 1:
              tmpBuffer[0] = PREFIX_SLASH_POOL;
              break;
            case 2:
              tmpBuffer[0] = PREFIX_PARAMETERS;
              break;
            case 3:
              tmpBuffer[0] = PREFIX_IBC;
              break;
            case 4:
              tmpBuffer[0] = PREFIX_IBC_TOKEN;
              MEMCPY(tmpBuffer + 1, addr->Internal.IbcToken.ibcTokenHash.ptr, 20);
              break;
            case 5:
              tmpBuffer[0] = PREFIX_GOVERNANCE;
              break;
            case 6:
              tmpBuffer[0] = PREFIX_ETH_BRIDGE;
              break;
            case 7:
              tmpBuffer[0] = PREFIX_BRIDGE_POOL;
              break;
            case 8:
              tmpBuffer[0] = PREFIX_ERC20;
              MEMCPY(tmpBuffer + 1, addr->Internal.Erc20.erc20Addr.ptr, 20);
              break;
            case 9:
              tmpBuffer[0] = PREFIX_NUT;
              MEMCPY(tmpBuffer + 1, addr->Internal.Nut.ethAddr.ptr, 20);
              break;
            case 10:
              tmpBuffer[0] = PREFIX_MULTITOKEN;
              break;
            case 11:
              tmpBuffer[0] = PREFIX_PGF;
              break;
            case 12:
              tmpBuffer[0] = PREFIX_MASP;
              break;
            case 13:
              tmpBuffer[0] = PREFIX_TMP_STORAGE;
              break;
            }
            break;

        default:
            return parser_value_out_of_range;
    }

    char HRP[12] = MAINNET_ADDRESS_T_HRP;
    // Check HRP for mainnet/testnet
#if defined(LEDGER_SPECIFIC)
    if (hdPath[1] == HDPATH_1_TESTNET) {
        strcpy(HRP, TESTNET_ADDRESS_T_HRP);
    }
#endif

    const zxerr_t err = bech32EncodeFromBytes(address,
                                addressLen,
                                HRP,
                                (uint8_t*) tmpBuffer,
                                ADDRESS_LEN_BYTES,
                                1,
                                BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

zxerr_t crypto_sha256(const uint8_t *input, uint16_t inputLen, uint8_t *output, uint16_t outputLen) {
    if (input == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_encoding_failed;
    }

    MEMZERO(output, outputLen);

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_hash_sha256(input, inputLen, output, CX_SHA256_SIZE);
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, input, inputLen);
    picohash_final(&ctx, output);
#endif
    return zxerr_ok;
}

zxerr_t crypto_computeCodeHash(section_t *extraData) {
    if (extraData == NULL) {
        return zxerr_invalid_crypto_settings;
    }

    if (extraData->commitmentDiscriminant) {
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
        cx_sha256_t sha256 = {0};
        cx_sha256_init(&sha256);
        CHECK_CX_OK(cx_sha256_update(&sha256, extraData->bytes.ptr, extraData->bytes.len));
        CHECK_CX_OK(cx_sha256_final(&sha256, extraData->bytes_hash));
#else
        picohash_ctx_t sha256 = {0};
        picohash_init_sha256(&sha256);
        picohash_update(&sha256, extraData->bytes.ptr, extraData->bytes.len);
        picohash_final(&sha256, extraData->bytes_hash);
#endif
    }
    return zxerr_ok;
}

zxerr_t crypto_hashExtraDataSection(const section_t *extraData, uint8_t *output, uint32_t outputLen) {
    if (extraData == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_invalid_crypto_settings;
    }

    const uint32_t extraDataTagLen = extraData->tag.len;
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, &extraData->discriminant, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, extraData->salt.ptr, extraData->salt.len));
    CHECK_CX_OK(cx_sha256_update(&sha256, extraData->bytes_hash, sizeof(extraData->bytes_hash)));
    uint8_t has_tag = (extraData->tag.ptr == NULL) ? 0 : 1;
    CHECK_CX_OK(cx_sha256_update(&sha256, &has_tag, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &extraDataTagLen, has_tag*sizeof(extraDataTagLen)));
    CHECK_CX_OK(cx_sha256_update(&sha256, extraData->tag.ptr, has_tag*extraDataTagLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
#else
    picohash_ctx_t sha256 = {0};
    picohash_init_sha256(&sha256);
    picohash_update(&sha256, &extraData->discriminant, 1);
    picohash_update(&sha256, extraData->salt.ptr, extraData->salt.len);
    picohash_update(&sha256, extraData->bytes_hash, sizeof(extraData->bytes_hash));
    uint8_t has_tag = (extraData->tag.ptr == NULL) ? 0 : 1;
    picohash_update(&sha256, &has_tag, 1);
    picohash_update(&sha256, (uint8_t*) &extraDataTagLen, has_tag*sizeof(extraDataTagLen));
    picohash_update(&sha256, extraData->tag.ptr, has_tag*extraDataTagLen);
    picohash_final(&sha256, output);
#endif

    return zxerr_ok;
}

zxerr_t crypto_hashDataSection(const section_t *data, uint8_t *output, uint32_t outputLen) {
    if (data == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_no_data;
    }

    const uint32_t dataBytesLen = data->bytes.len;
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, &data->discriminant, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, data->salt.ptr, data->salt.len));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &dataBytesLen, sizeof(dataBytesLen)));
    CHECK_CX_OK(cx_sha256_update(&sha256, data->bytes.ptr, dataBytesLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
#else
    picohash_ctx_t sha256 = {0};
    picohash_init_sha256(&sha256);
    picohash_update(&sha256, &data->discriminant, 1);
    picohash_update(&sha256, data->salt.ptr, data->salt.len);
    picohash_update(&sha256, (uint8_t*) &dataBytesLen, sizeof(dataBytesLen));
    picohash_update(&sha256, data->bytes.ptr, dataBytesLen);
    picohash_final(&sha256, output);
#endif

    return zxerr_ok;
}

zxerr_t crypto_hashCodeSection(const section_t *code, uint8_t *output, uint32_t outputLen) {
    if (code == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }

    const uint32_t codeTagLen = code->tag.len;
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, &code->discriminant, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, code->salt.ptr, code->salt.len));
    CHECK_CX_OK(cx_sha256_update(&sha256, code->bytes_hash, sizeof(code->bytes_hash)));
    uint8_t has_tag = (code->tag.ptr == NULL) ? 0 : 1;
    CHECK_CX_OK(cx_sha256_update(&sha256, &has_tag, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &codeTagLen, has_tag*sizeof(codeTagLen)));
    CHECK_CX_OK(cx_sha256_update(&sha256, code->tag.ptr, has_tag*codeTagLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
#else
    picohash_ctx_t sha256 = {0};
    picohash_init_sha256(&sha256);
    picohash_update(&sha256, &code->discriminant, 1);
    picohash_update(&sha256, code->salt.ptr, code->salt.len);
    picohash_update(&sha256, code->bytes_hash, sizeof(code->bytes_hash));
    uint8_t has_tag = (code->tag.ptr == NULL) ? 0 : 1;
    picohash_update(&sha256, &has_tag, 1);
    picohash_update(&sha256, (uint8_t*) &codeTagLen, has_tag*sizeof(codeTagLen));
    picohash_update(&sha256, code->tag.ptr, has_tag*codeTagLen);
    picohash_final(&sha256, output);
#endif

    return zxerr_ok;
}

zxerr_t crypto_serializeCodeHash(uint8_t *buffer, uint16_t bufferLen) {
    if (bufferLen < 2) {
        return zxerr_buffer_too_small;
    }

    MEMZERO(buffer, bufferLen);
    buffer[0] = 10;
    buffer[1] = CX_SHA256_SIZE;

    return zxerr_ok;
}

zxerr_t crypto_serializeData(const uint64_t dataSize, uint8_t *buffer, uint16_t bufferLen, uint8_t *dataInfoSize) {
    if (bufferLen < 11) {
        return zxerr_buffer_too_small;
    }

    MEMZERO(buffer, bufferLen);
    buffer[0] = 18;
    CHECK_ZXERR(encodeLEB128(dataSize, buffer + 1, MAX_LEB128_OUTPUT, dataInfoSize))

    (*dataInfoSize)++;
    return zxerr_ok;
}

// MASP Section
parser_error_t convertKey(const uint8_t spendingKey[KEY_LENGTH], const uint8_t modifier, uint8_t outputKey[KEY_LENGTH],
                          bool reduceWideByte) {
    uint8_t output[64] = {0};
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)EXPANDED_SPEND_BLAKE2_KEY,
                                           sizeof(EXPANDED_SPEND_BLAKE2_KEY)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, spendingKey, KEY_LENGTH));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, &modifier, 1));
    cx_blake2b_final(&ctx, output);
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t *)EXPANDED_SPEND_BLAKE2_KEY,
                                      sizeof(EXPANDED_SPEND_BLAKE2_KEY));
    blake2b_update(&state, spendingKey, KEY_LENGTH);
    blake2b_update(&state, &modifier, 1);
    blake2b_final(&state, output, sizeof(output));
#endif

     if (reduceWideByte) {
         from_bytes_wide(output, outputKey);
     } else {
        memcpy(outputKey, output, KEY_LENGTH);
    }

    return parser_ok;
}

parser_error_t generate_key(const uint8_t expandedKey[KEY_LENGTH], constant_key_t keyType, uint8_t output[KEY_LENGTH]) {
    if (keyType >= InvalidKey) {
        return parser_value_out_of_range;
    }
    uint8_t tmpExpandedKey[KEY_LENGTH] = {0};
    memcpy(tmpExpandedKey, expandedKey, KEY_LENGTH);
    scalar_multiplication(tmpExpandedKey, keyType, output);

    return parser_ok;
}

parser_error_t computeIVK(const ak_t ak, const nk_t nk, ivk_t ivk) {
    blake2s_state state = {0};
    blake2s_init_with_personalization(&state, 32, (const uint8_t *)CRH_IVK_PERSONALIZATION, sizeof(CRH_IVK_PERSONALIZATION));
    blake2s_update(&state, ak, KEY_LENGTH);
    blake2s_update(&state, nk, KEY_LENGTH);
    blake2s_final(&state, ivk, KEY_LENGTH);

    ivk[31] &= 0x07;

    return parser_ok;
}

parser_error_t computeMasterFromSeed(const uint8_t seed[KEY_LENGTH],  uint8_t master_sk[KEY_LENGTH]) {
    if(seed == NULL || master_sk == NULL) {
        return parser_unexpected_error;
    }
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)SAPLING_MASTER_PERSONALIZATION,
                                           sizeof(SAPLING_MASTER_PERSONALIZATION)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, seed, KEY_LENGTH));
    cx_blake2b_final(&ctx, master_sk);
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t *)SAPLING_MASTER_PERSONALIZATION,
                                      sizeof(SAPLING_MASTER_PERSONALIZATION));
    blake2b_update(&state, seed, KEY_LENGTH);
    blake2b_final(&state, master_sk, EXTENDED_KEY_LENGTH);
#endif

    return parser_ok;
}

bool check_diversifier(const uint8_t d[DIVERSIFIER_LENGTH]) {
    if(d == NULL) {
        return parser_unexpected_error;
    }

    uint8_t hash[32] = {0};

    blake2s_state state = {0};
    blake2s_init_with_personalization(&state, 32, (const uint8_t *)KEY_DIVERSIFICATION_PERSONALIZATION, sizeof(KEY_DIVERSIFICATION_PERSONALIZATION));
    blake2s_update(&state, (const uint8_t *)GH_FIRST_BLOCK, sizeof(GH_FIRST_BLOCK));
    blake2s_update(&state, d, DIVERSIFIER_LENGTH);
    blake2s_final(&state, hash, KEY_LENGTH);

    return is_valid_diversifier(hash);
}

// Derive the asset type corresponding to the given asset data
parser_error_t derive_asset_type(const masp_asset_data_t *asset_data, uint8_t *identifier, uint8_t *nonce) {
    if(asset_data == NULL || nonce == NULL) {
        return parser_unexpected_error;
    }

    for(*nonce = 0; *nonce <= 255; (*nonce) ++) {
        blake2s_state ai_state = {0};
        blake2s_init_with_personalization(&ai_state, 32, (const uint8_t *)ASSET_IDENTIFIER_PERSONALIZATION, sizeof(ASSET_IDENTIFIER_PERSONALIZATION));
        blake2s_update(&ai_state, (const uint8_t *)GH_FIRST_BLOCK, sizeof(GH_FIRST_BLOCK));
        blake2s_update(&ai_state, asset_data->bytes.ptr, asset_data->bytes.len);
        blake2s_update(&ai_state, nonce, sizeof(*nonce));
        blake2s_final(&ai_state, identifier, ASSET_IDENTIFIER_LENGTH);

        uint8_t hash[32] = {0};
        blake2s_state vcg_state = {0};
        blake2s_init_with_personalization(&vcg_state, 32, (const uint8_t *)VALUE_COMMITMENT_GENERATOR_PERSONALIZATION, sizeof(VALUE_COMMITMENT_GENERATOR_PERSONALIZATION));
        blake2s_update(&vcg_state, identifier, KEY_LENGTH);
        blake2s_final(&vcg_state, hash, KEY_LENGTH);

        if(is_valid_diversifier(hash)) {
          return parser_ok;
        }
    }

    return parser_unexpected_error;
}

// Return list with 4 diversifiers, starting computing form start_index
parser_error_t computeDiversifiersList(const uint8_t dk[KEY_LENGTH], uint8_t start_index[DIVERSIFIER_LENGTH], uint8_t diversifier_list[DIVERSIFIER_LIST_LENGTH]) {
    if(dk == NULL || start_index == NULL || diversifier_list == NULL) {
        return parser_unexpected_error;
    }

   return get_default_diversifier_list(dk, start_index, diversifier_list);
}

static bool reached_max_index(uint8_t diversifier_index[DIVERSIFIER_LENGTH]) {
    for (int i = 0; i < DIVERSIFIER_LENGTH; i++) {
        if (diversifier_index[i] != UINT8_MAX) {
            return false;
        }
    }
    return true;
}
// Return a valid diversifier from the diversifier list, if not found, compute a new list, strating from the incremented
// start_index
parser_error_t computeDiversifier(const uint8_t dk[KEY_LENGTH], uint8_t start_index[DIVERSIFIER_LENGTH], uint8_t diversifier[DIVERSIFIER_LENGTH]) {
    bool found = false;
    uint8_t diversifier_list[DIVERSIFIER_LIST_LENGTH] = {0};

    while (!found)
    {
        CHECK_ERROR(computeDiversifiersList(dk, start_index, diversifier_list));
        for (uint8_t i = 0; i < 4; i++)
        {
            uint8_t d[DIVERSIFIER_LENGTH] = {0};
            memcpy(d, diversifier_list + i*DIVERSIFIER_LENGTH, DIVERSIFIER_LENGTH);
            if (check_diversifier(d) && !found)
            {
               memcpy(diversifier, d, DIVERSIFIER_LENGTH);
               found = true;
               break;
            }
        }

        if (reached_max_index(start_index))
        {
            return parser_diversifier_not_found;
        }
    }

    return parser_ok;
}

parser_error_t computePkd(const uint8_t ivk[KEY_LENGTH], const uint8_t diversifier[DIVERSIFIER_LENGTH], uint8_t pk_d[KEY_LENGTH]) {
    if(ivk == NULL || diversifier == NULL || pk_d == NULL) {
        return parser_unexpected_error;
    }

    uint8_t hash[32] = {0};

    blake2s_state state = {0};
    blake2s_init_with_personalization(&state, 32, (const uint8_t *)KEY_DIVERSIFICATION_PERSONALIZATION, sizeof(KEY_DIVERSIFICATION_PERSONALIZATION));
    blake2s_update(&state, (const uint8_t *)GH_FIRST_BLOCK, sizeof(GH_FIRST_BLOCK));
    blake2s_update(&state, diversifier, DIVERSIFIER_LENGTH);
    blake2s_final(&state, hash, KEY_LENGTH);

    CHECK_ERROR(get_pkd(ivk, hash, pk_d));
    return parser_ok;
}

static void u64_to_bytes(uint64_t value, uint8_t array[32]) {
    MEMZERO(array, 32);

    // Fill the first 8 bytes with the uint64_t value in little-endian order
    for (int i = 0; i < 8; i++) {
        array[i] = (value >> (i * 8)) & 0xFF;
    }
}

//https://github.com/anoma/masp/blob/main/masp_primitives/src/sapling.rs#L194
parser_error_t computeValueCommitment(uint64_t value, uint8_t *rcv, uint8_t *identifier, uint8_t *cv) {
    if(rcv == NULL || identifier == NULL || cv == NULL) {
        return parser_unexpected_error;
    }

    uint8_t value_bytes[32] = {0};
    u64_to_bytes(value, value_bytes);

    uint8_t hash[32] = {0};
    blake2s_state state = {0};
    blake2s_init_with_personalization(&state, 32, (const uint8_t *)VALUE_COMMITMENT_GENERATOR_PERSONALIZATION, sizeof(VALUE_COMMITMENT_GENERATOR_PERSONALIZATION));
    blake2s_update(&state, identifier, KEY_LENGTH);
    blake2s_final(&state, hash, KEY_LENGTH);

    uint8_t scalar[32] = {0};
    CHECK_ERROR(parser_scalar_multiplication(rcv, ValueCommitmentRandomnessGenerator, scalar));
    CHECK_ERROR(add_points(hash, value_bytes, scalar, cv));

    return parser_ok;
}

parser_error_t computeConvertValueCommitment(uint64_t value, uint8_t *rcv, uint8_t *generator, uint8_t *cv) {
    if(rcv == NULL || generator == NULL || cv == NULL) {
        return parser_unexpected_error;
    }

    uint8_t value_bytes[32] = {0};
    u64_to_bytes(value, value_bytes);

    uint8_t scalar[32] = {0};
    CHECK_ERROR(parser_scalar_multiplication(rcv, ValueCommitmentRandomnessGenerator, scalar));
    CHECK_ERROR(add_points(generator, value_bytes, scalar, cv));

    return parser_ok;
}


parser_error_t computeRk(keys_t *keys, uint8_t *alpha, uint8_t *rk) {
    if(keys == NULL || alpha == NULL || rk == NULL) {
        return parser_unexpected_error;
    }
    uint8_t rsk[KEY_LENGTH] = {0};
    // get randomized secret
    CHECK_ERROR(parser_randomized_secret_from_seed(keys->ask, alpha, rsk));

    //rsk to rk
    CHECK_ERROR(parser_scalar_multiplication(rsk, SpendingKeyGenerator, rk));

    return parser_ok;
}

parser_error_t h_star(uint8_t *a, uint16_t a_len, uint8_t *b, uint16_t b_len, uint8_t *output) {
    if (a == NULL || b == NULL || output == NULL) {
        return parser_no_data;
    }

    uint8_t hash[BLAKE2B_OUTPUT_LEN] = {0};
#if defined(LEDGER_SPECIFIC)
    cx_blake2b_t ctx = {0};
    ASSERT_CX_OK(cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, (uint8_t *)SIGNING_REDJUBJUB,
                                           sizeof(SIGNING_REDJUBJUB)));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, a, a_len));
    ASSERT_CX_OK(cx_blake2b_update(&ctx, b, b_len));
    cx_blake2b_final(&ctx, hash);
#else
    blake2b_state state = {0};
    blake2b_init_with_personalization(&state, BLAKE2B_OUTPUT_LEN, (const uint8_t *)SIGNING_REDJUBJUB,
                                      sizeof(SIGNING_REDJUBJUB));
    blake2b_update(&state, a, a_len);
    blake2b_update(&state, b, b_len);
    blake2b_final(&state, hash, BLAKE2B_OUTPUT_LEN);
#endif

    from_bytes_wide(hash, output);

    return parser_ok;
}

// This fuctnion will allow to test the rust ones in cpp_tests
parser_error_t parser_scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]) {
    if (input == NULL || output == NULL) {
        return parser_no_data;
    }

    return scalar_multiplication(input, key, output);
}

parser_error_t parser_compute_sbar(const uint8_t s[32], uint8_t r[32], uint8_t rsk[32], uint8_t sbar[32]) {
    if (s == NULL || r == NULL || rsk == NULL || sbar == NULL) {
        return parser_no_data;
    }

    return compute_sbar(s, r, rsk, sbar);
}

parser_error_t parser_randomized_secret_from_seed(const uint8_t ask[32], const uint8_t alpha[32], uint8_t output[32]) {
    if (ask == NULL || alpha == NULL || output == NULL) {
        return parser_no_data;
    }

    return randomized_secret_from_seed(ask, alpha, output);
}
