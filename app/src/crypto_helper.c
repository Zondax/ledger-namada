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

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    #include "cx.h"
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
    cx_hash_sha256(borshEncodedPubKey, PK_LEN_25519 + 1, pkh, CX_SHA256_SIZE);
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

    const uint8_t addressLen = ADDRESS_LEN;
    memcpy(buffer, addr_out, ADDRESS_LEN);
    return addressLen;
}