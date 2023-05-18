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

#define CLA                             0x57

#define HDPATH_LEN_DEFAULT   5
#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)   //44

#define HDPATH_1_DEFAULT     (0x80000000u | 0x36d)  //877
#define HDPATH_1_TESTNET     (0x80000000u | 0x36d)  //877

#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define SECP256K1_PK_LEN            65u
#define SECP256K1_SK_LEN            32u
#define SCALAR_LEN_SECP256K1        32u

#define SK_LEN_25519 64u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define ED25519_SIGNATURE_SIZE 64u

#define PK_LEN_25519 32u
#define PK_HASH_LEN 40u

#define ADDRESS_LEN_MAINNET 80u
#define ADDRESS_LEN_TESTNET 84u

#define SALT_LEN     8
#define HASH_LEN    32
#define SIG_R_LEN   32
#define SIG_S_LEN   32
#define SIG_ED25519_LEN (SIG_R_LEN + SIG_S_LEN)

#define MAX_BECH32_HRP_LEN  83u

/// An address string before bech32m encoding must be this size.
#define FIXED_LEN_STRING_BYTES 45u

/// For payment addresses on the Testnet, the Human-Readable Part is "patest"
#define SAPLING_PAYMENT_ADDR_HRP "patest"

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "NAM "

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

#define INS_SIGN_WRAPPER                0x02

#define INS_GET_SHIELDED_ADDRESS 0x10
#define INS_INIT_MASP_TRANSFER 0xe0
#define INS_GET_IVK 0xf0
#define INS_GET_OVK 0xf1
#define INS_GET_NF 0xf2

#define INS_GET_SIGNATURE 0x0A

#ifdef __cplusplus
}
#endif
