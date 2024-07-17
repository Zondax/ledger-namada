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

#if defined (LEDGER_SPECIFIC)
// blake2 needs to define output size in bits 512 bits = 64 bytes
#define BLAKE2B_OUTPUT_LEN 512
#else
#define BLAKE2B_OUTPUT_LEN 64
#endif

const char SAPLING_MASTER_PERSONALIZATION[16] = "MASP_IP32Sapling";
const char EXPANDED_SPEND_BLAKE2_KEY[16] = "MASP__ExpandSeed";
const char CRH_IVK_PERSONALIZATION[8] = "MASP_ivk";
const char KEY_DIVERSIFICATION_PERSONALIZATION[8] = "MASP__gd";
const char ASSET_IDENTIFIER_PERSONALIZATION[8] = "MASP__t_";
const char GH_FIRST_BLOCK[64] = "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";
const char SIGNING_REDJUBJUB[16] = "MASP__RedJubjubH";
const char VALUE_COMMITMENT_GENERATOR_PERSONALIZATION[8] = "MASP__v_";
#ifdef __cplusplus
}
#endif
