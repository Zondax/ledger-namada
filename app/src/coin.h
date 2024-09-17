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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define CLA                             0x57

#define HDPATH_LEN_DEFAULT   5
#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)   //44

#define HDPATH_1_DEFAULT     (0x80000000u | 0x36d)  //877
#define HDPATH_1_TESTNET     (0x80000000u | 0x01)  //1

#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define SECP256K1_PK_LEN            65u
#define COMPRESSED_SECP256K1_PK_LEN 33u
#define SECP256K1_SK_LEN            32u
#define SCALAR_LEN_SECP256K1        32u
#define ETH_ADDRESS_LEN             20u

#define SK_LEN_25519 32u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define ED25519_SIGNATURE_SIZE 64u

#define PK_LEN_25519 32u
#define PK_HASH_LEN 20u
#define PK_HASH_STR_LEN 40u

// Extra byte at the beginning to indicate type (ED25519 = 0)
#define PK_LEN_25519_PLUS_TAG 33u
#define SIG_LEN_25519_PLUS_TAG 65u

#define ADDRESS_LEN_BYTES   21

#define ADDRESS_LEN_MAINNET 45u
#define PUBKEY_LEN_MAINNET 66u

#define ADDRESS_LEN_TESTNET 49u
#define PUBKEY_LEN_TESTNET 70u

#define SALT_LEN     8
#define HASH_LEN    32
#define SIG_R_LEN   32
#define SIG_S_LEN   32
#define SIG_ED25519_LEN (SIG_R_LEN + SIG_S_LEN)
#define SIG_SECP256K1_LEN 65
#define MASP_SIG_LEN 64

#define MAX_BECH32_HRP_LEN  83u

/// For payment addresses on the Testnet, the Human-Readable Part is "patest"
#define SAPLING_PAYMENT_ADDR_HRP "patest"

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "NAM "

#define POS_DECIMAL_PRECISION 12

#define MENU_MAIN_APP_LINE1 "Namada"
#define MENU_MAIN_APP_LINE2 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET  "???"
#define APPVERSION_LINE1 "Namada"
#define APPVERSION_LINE2 "v" APPVERSION

typedef enum {
    key_ed25519 = 0,
    key_secp256k1 = 1,
} signing_key_type_e;

typedef enum {
    PublicAddress = 0,
    ViewKeys = 1,
    ProofGenerationKey = 2,
    InvalidKey,
} key_kind_e;

typedef enum {
    spend = 0,
    output,
    convert
} masp_type_e;

#define INS_GET_KEYS                    0x03
#define INS_GET_SPEND_RAND              0x04
#define INS_GET_OUTPUT_RAND             0x05
#define INS_GET_CONVERT_RAND            0x06
#define INS_SIGN_MASP_SPENDS            0x07
#define INS_EXTRACT_SPEND_SIGN          0x08
#define INS_CLEAN_BUFFERS               0x09

#define APDU_CODE_CHECK_SIGN_TR_FAIL 0x6999
#ifdef __cplusplus
}
#endif
