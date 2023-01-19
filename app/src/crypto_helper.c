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
#include "crypto_helper.h"
#include "coin.h"
#include "bech32.h"
#include "zxformat.h"
#include "leb128.h"

#ifdef LEDGER_SPECIFIC
#include "bolos_target.h"
#endif

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    #include "cx.h"
    #include "cx_sha256.h"
#else
    #include "picohash.h"
    #define CX_SHA256_SIZE 32
#endif

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
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
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
    snprintf((char*) publicKeyHash, FIXED_LEN_STRING_BYTES, "imp::");

    // Step 4. The Public Key Hash consists of the first 40 characters of the hex encoding. ---> UPPERCASE
    MEMCPY(publicKeyHash + 5, hexPubKeyHash, PK_HASH_LEN);

    return zxerr_ok;
}

uint8_t crypto_encodePubkey_ed25519(uint8_t *buffer, uint16_t bufferLen, const uint8_t *pubkey, bool isTestnet) {
    if (buffer == NULL || pubkey == NULL) {
        return 0;
    }

    if (bufferLen < ADDRESS_LEN_MAINNET || (bufferLen < ADDRESS_LEN_TESTNET && isTestnet)) {
        return 0;
    }

    const char *hrp = isTestnet ? "atest" : "a";

    // Step 1:  Compute the hash of the Ed25519 public key
    uint8_t publicKeyHash[FIXED_LEN_STRING_BYTES] = {0};
    crypto_publicKeyHash_ed25519(publicKeyHash, pubkey);

    // Step 2. Encode the public key hash with bech32m
    char addr_out[110] = {0};
    zxerr_t err = bech32EncodeFromBytes(addr_out,
                                        sizeof(addr_out),
                                        hrp,
                                        publicKeyHash,
                                        sizeof(publicKeyHash),
                                        0,
                                        BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok){
        return 0;
    }

    const uint8_t addressLen = isTestnet ? ADDRESS_LEN_TESTNET : ADDRESS_LEN_MAINNET;
    memcpy(buffer, addr_out, addressLen);
    return addressLen;
}

zxerr_t crypto_sha256(const uint8_t *input, uint16_t inputLen, uint8_t *output, uint16_t outputLen) {
    if (input == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_encoding_failed;
    }

    MEMZERO(output, outputLen);

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_hash_sha256(input, inputLen, output, CX_SHA256_SIZE);
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, input, inputLen);
    picohash_final(&ctx, output);
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

zxerr_t crypto_serializeTimestamp(const prototimestamp_t *timestamp, uint8_t *buffer, uint16_t bufferLen, uint8_t *timestampSize) {
    if (timestamp == NULL || buffer == NULL || timestampSize == NULL) {
        return zxerr_encoding_failed;
    }
    MEMZERO(buffer, bufferLen);
    *timestampSize = 0;

    uint8_t offset = 0;
    buffer[offset++] = 0x1A; // TAG_TS
    buffer[offset++] = 0x00; // Size (reserved)

    uint8_t tmpLebSize = 0;
    if (timestamp->seconds > 0) {
        buffer[offset++] = 0x08; //TAG_S
        CHECK_ZXERR(encodeLEB128(timestamp->seconds, buffer + offset, MAX_LEB128_OUTPUT, &tmpLebSize))
        offset += tmpLebSize;
    }

    if (timestamp->nanos > 0) {
        buffer[offset++] = 0x10; //TAG_N
        CHECK_ZXERR(encodeLEB128(timestamp->nanos, buffer + offset, MAX_LEB128_OUTPUT, &tmpLebSize))
        offset += tmpLebSize;
    }

    // Update size with correct value
    buffer[1] = offset - 2;
    *timestampSize = offset; // Total size timestamp serialized struct
    return zxerr_ok;
}

zxerr_t crypto_getBytesToSign(const outer_layer_tx_t *outerTxn, uint8_t *toSign, size_t toSignLen) {
    if (outerTxn == NULL || toSign == NULL || toSignLen < CX_SHA256_SIZE) {
        return zxerr_encoding_failed;
    }

    MEMZERO(toSign, toSignLen);

    uint8_t code_hash[32] = {0};
    CHECK_ZXERR(crypto_sha256(outerTxn->code, outerTxn->codeSize, (uint8_t*) &code_hash, sizeof(code_hash)))

    uint8_t tmpBuff[20] = {0};
    uint8_t tmpSize = 0;
    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);

    // Code - Code hash
    CHECK_ZXERR(crypto_serializeCodeHash((uint8_t*) tmpBuff, sizeof(tmpBuff)))
    cx_sha256_update(&ctx, (const uint8_t*) tmpBuff, 2);
    cx_sha256_update(&ctx, (const uint8_t*) code_hash, sizeof(code_hash));

    // Data
    CHECK_ZXERR(crypto_serializeData((const uint64_t)outerTxn->dataSize, (uint8_t*) tmpBuff, sizeof(tmpBuff), &tmpSize))
    cx_sha256_update(&ctx, (const uint8_t*) tmpBuff, tmpSize);
    cx_sha256_update(&ctx, outerTxn->data, outerTxn->dataSize);

    // Timestamp
    CHECK_ZXERR(crypto_serializeTimestamp(&outerTxn->timestamp, (uint8_t*) tmpBuff, sizeof(tmpBuff), &tmpSize))
    cx_sha256_update(&ctx, (const uint8_t*) tmpBuff, tmpSize);


    // Hash SigningTxn
    cx_sha256_final(&ctx, toSign);
    #else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);

    // Code - Code hash
    CHECK_ZXERR(crypto_serializeCodeHash((uint8_t*) tmpBuff, sizeof(tmpBuff)))
    picohash_update(&ctx, tmpBuff, 2);
    picohash_update(&ctx, code_hash, sizeof(code_hash));

    // Data
    CHECK_ZXERR(crypto_serializeData((const uint64_t)outerTxn->dataSize, (uint8_t*) tmpBuff, sizeof(tmpBuff), &tmpSize))
    picohash_update(&ctx, &tmpBuff, tmpSize);
    picohash_update(&ctx, outerTxn->data, outerTxn->dataSize);

    // Timestamp
    CHECK_ZXERR(crypto_serializeTimestamp(&outerTxn->timestamp, (uint8_t*) tmpBuff, sizeof(tmpBuff), &tmpSize))
    picohash_update(&ctx, tmpBuff, tmpSize);

    picohash_final(&ctx, toSign);
    #endif

    return zxerr_ok;
}
