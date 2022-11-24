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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// #{TODO} ---> Replace CLA, Token symbol, HDPATH, etc etc
#define CLA                             0x57

#define HDPATH_LEN_DEFAULT   5
#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)   //44
// TODO: Change 283' to whatever the namada slip-0010 coin type will be.
#define HDPATH_1_DEFAULT     (0x80000000u | 0x11b)  //283

#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define SECP256K1_PK_LEN            65u
#define SECP256K1_SK_LEN            32u
#define SCALAR_LEN_SECP256K1        32u

#define SK_LEN_25519 64u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define PK_LEN_25519 32u
#define PK_HASH_LEN 40u
#define ADDRESS_HRP_LEN 5
/// The length of [`Address`] encoded with Bech32m.
#define ADDRESS_LEN 79 + ADDRESS_HRP_LEN
#define FIXED_LEN_STRING_BYTES 45u

/// For payment addresses on the Testnet, the Human-Readable Part is "patest"
#define SAPLING_PAYMENT_ADDR_HRP "patest"

/// The length of [`Address`] encoded with Bech32m.
#define ADDRESS_LEN 79 + ADDRESS_HRP_LEN

#define MAX_SIGN_SIZE 256u
#define BLAKE2B_DIGEST_SIZE 32u

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "TODO "

#define MENU_MAIN_APP_LINE1 "Namada"
#define MENU_MAIN_APP_LINE2 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET          "???"
#define APPVERSION_LINE1 "Namada"
#define APPVERSION_LINE2 "v" APPVERSION

typedef enum {
    key_ed25519 = 0,
    key_secp256k1 = 1,
} signing_key_type_e;

typedef enum {
    addr_masp_transparent_secp256k1 = 0,
    addr_masp_shielded = 1, // was addr_sapling
    addr_masp_shielded_div = 2,
} address_kind_e;

typedef enum {
    key_ivk = 0,
    key_ovk = 1,
    key_fvk = 2,
    nf = 3
} key_type_e;

#ifdef __cplusplus
}
#endif
