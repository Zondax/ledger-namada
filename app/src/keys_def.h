/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

#include <stddef.h>
#include <stdint.h>
#include "parser_types.h"

typedef enum {
    SpendingKeyGenerator,
    ProofGenerationKeyGenerator,
    PublicKeyGenerator,
    ValueCommitmentRandomnessGenerator,
} constant_key_t;

#define RNG_LEN 80
#define KEY_LENGTH 32
#define ASSET_IDENTIFIER_LENGTH 32
#define EXTENDED_KEY_LENGTH 64
#define DIVERSIFIER_LENGTH 11
#define DIVERSIFIER_LIST_LENGTH 44
typedef uint8_t spending_key_t[KEY_LENGTH];
typedef uint8_t ask_t[KEY_LENGTH];
typedef uint8_t nsk_t[KEY_LENGTH];

typedef uint8_t ak_t[KEY_LENGTH];
typedef uint8_t nk_t[KEY_LENGTH];

typedef uint8_t dk_t[KEY_LENGTH];
typedef uint8_t ivk_t[KEY_LENGTH];
typedef uint8_t ovk_t[KEY_LENGTH];
typedef uint8_t d_t[DIVERSIFIER_LENGTH];

typedef uint8_t public_address_t[KEY_LENGTH];

typedef struct {
    char viewKey[2*KEY_LENGTH];
    char ovk[KEY_LENGTH];
    char ivk[KEY_LENGTH];
    char dk[KEY_LENGTH];
} KeyData;

typedef struct {
    spending_key_t spendingKey;
    ask_t ask;
    ak_t ak;
    nsk_t nsk;
    nk_t nk;
    dk_t dk;
    ivk_t ivk;
    ovk_t ovk;
    d_t diversifier;
    d_t diversifier_start_index;
    public_address_t address;
} keys_t;

#ifdef __cplusplus
}
#endif
