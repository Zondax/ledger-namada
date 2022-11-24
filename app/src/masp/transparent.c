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

#include <stdio.h>
#include "coin.h"
#include "constants.h"
#include "zxerror.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "app_mode.h"
#include "crypto.h"

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t address[50];
} __attribute__((packed)) answer_t;

// According to Sapling 5.6 Encodings of Addresses and Keys
typedef struct {
    // [ADDRESS                              ]
    // [EXTENDED RIPEMD-160][Checksum 4-bytes]
    // [EXTENDED RIPEMD-160][Checksum-------------------------]
    // [version][RIPEMD-160]
    union {
        uint8_t address[VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE];

        struct {
            uint8_t extended_ripe[VERSION_SIZE + CX_RIPEMD160_SIZE];
            uint8_t sha256_checksum[CX_SHA256_SIZE];
        };

        union {
            // [EXTENDED RIPEMD-160]
            // [version][RIPEMD-160]
            struct {
                uint8_t version[VERSION_SIZE];
                uint8_t ripe_sha256_pk[CX_RIPEMD160_SIZE];
            };
        };
    };

    // Temporary buffers
    union {
        uint8_t sha256_pk[CX_SHA256_SIZE];
        uint8_t sha256_extended_ripe[CX_SHA256_SIZE];
    };
} __attribute__((packed)) address_temp_t;

// handleGetAddrSecp256K1
zxerr_t masp_transparent_get_address_secp256k1(uint8_t *buffer, uint16_t buffer_len, uint16_t *replyLen) {
    if (buffer_len < sizeof(answer_t)) {
        *replyLen =  0;
        return zxerr_unknown;
    }

    zemu_log_stack("masp_transparent_get_address_secp256k1");

    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKey_secp256k1(answer->publicKey, sizeof_field(answer_t, publicKey)));

    address_temp_t address_temp;

    // extended-ripemd-160 = [version][ripemd-160(sha256(pk))]
    address_temp.version[0] = VERSION_P2PKH >> 8;
    address_temp.version[1] = VERSION_P2PKH & 0xFF;
    cx_hash_sha256(answer->publicKey, SECP256K1_PK_LEN, address_temp.sha256_pk, CX_SHA256_SIZE);      // SHA256
    ripemd160(address_temp.sha256_pk, CX_SHA256_SIZE, address_temp.ripe_sha256_pk);         // RIPEMD-160

    // checksum = sha256(sha256(extended-ripe))
    cx_hash_sha256(address_temp.extended_ripe, CX_RIPEMD160_SIZE + VERSION_SIZE, address_temp.sha256_extended_ripe, CX_SHA256_SIZE);
    cx_hash_sha256(address_temp.sha256_extended_ripe, CX_SHA256_SIZE, address_temp.sha256_checksum, CX_SHA256_SIZE);

    // 7. 25 bytes BTC address = [extended ripemd-160][checksum]
    // Encode as base58
    size_t outLen = sizeof_field(answer_t, address);
    int err = encode_base58(address_temp.address, VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE, answer->address, &outLen);
    if(err != 0){
        return zxerr_unknown;
    }
    *replyLen = SECP256K1_PK_LEN + outLen;
    return zxerr_ok;
}