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
#define TAG_LENGTH 4
#define ASSET_IDENTIFIER_LENGTH 32
#define EXTENDED_KEY_LENGTH 64
#define DIVERSIFIER_LENGTH 11
#define DIVERSIFIER_LIST_LENGTH 44
#define ZIP32_SEED_SIZE 64
typedef uint8_t spending_key_t[KEY_LENGTH];
typedef uint8_t ask_t[KEY_LENGTH];
typedef uint8_t nsk_t[KEY_LENGTH];

typedef uint8_t ak_t[KEY_LENGTH];
typedef uint8_t nk_t[KEY_LENGTH];

typedef uint8_t dk_t[KEY_LENGTH];
typedef uint8_t chain_code_t[KEY_LENGTH];
typedef uint8_t ivk_t[KEY_LENGTH];
typedef uint8_t ovk_t[KEY_LENGTH];
typedef uint8_t d_t[DIVERSIFIER_LENGTH];
typedef uint8_t fvk_tag_t[TAG_LENGTH];
typedef uint8_t fvk_t[KEY_LENGTH*3];

typedef uint8_t public_address_t[KEY_LENGTH];

typedef struct {
    ask_t ask;
    nsk_t nsk;
    fvk_t fvk;
    d_t diversifier;
    dk_t dk;
    chain_code_t chain_code;
    fvk_tag_t parent_fvk_tag;
    public_address_t address;
} keys_t;

#ifdef __cplusplus
}
#endif
