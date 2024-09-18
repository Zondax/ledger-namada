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

#include <stdint.h>
#include <stdbool.h>
#include "zxerror.h"
#include "parser_common.h"
#include "keys_def.h"

#define CODE_HASH_SIZE  32
#define TIMESTAMP_SIZE  14

#define CODE_HASH_INFO_SIZE 2

#define MODIFIER_ASK 0x00
#define MODIFIER_NSK 0x01
#define MODIFIER_OVK 0x02
#define MODIFIER_DK  0x10


#define ASSERT_CX_OK(CALL)      \
  do {                         \
    cx_err_t __cx_err = CALL;  \
    if (__cx_err != CX_OK) {   \
      return parser_unexpected_error;    \
    }                          \
  } while (0)

zxerr_t crypto_encodeRawPubkey(const uint8_t* rawPubkey, uint16_t rawPubkeyLen, uint8_t *output, uint16_t outputLen);
zxerr_t crypto_encodeAddress(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *output, uint16_t outputLen);

zxerr_t crypto_sha256(const uint8_t *input, uint16_t inputLen,
                      uint8_t *output, uint16_t outputLen);

zxerr_t crypto_computeCodeHash(section_t *extraData);
zxerr_t crypto_hashDataSection(const section_t *data, uint8_t *output, uint32_t outputLen);
zxerr_t crypto_hashCodeSection(const section_t *section, uint8_t *output, uint32_t outputLen);
zxerr_t crypto_hashExtraDataSection(const section_t *section, uint8_t *output, uint32_t outputLen);


// MASP SECTION
parser_error_t convertKey(const uint8_t spendingKey[KEY_LENGTH], const uint8_t modifier, uint8_t outputKey[KEY_LENGTH], bool reduceWideByte);
parser_error_t generate_key(const uint8_t expandedKey[KEY_LENGTH], constant_key_t keyType, uint8_t output[KEY_LENGTH]);
parser_error_t computeIVK(const ak_t ak, const nk_t nk, ivk_t ivk);
parser_error_t computeMasterFromSeed(const uint8_t seed[KEY_LENGTH],  uint8_t master_sk[EXTENDED_KEY_LENGTH]);
parser_error_t computeDiversifiersList(const uint8_t dk[KEY_LENGTH], uint8_t div_start_index[DIVERSIFIER_LENGTH], uint8_t diversifier_list[DIVERSIFIER_LIST_LENGTH]);
parser_error_t computeDiversifier(const uint8_t dk[KEY_LENGTH], uint8_t start_index[DIVERSIFIER_LENGTH], uint8_t diversifier[DIVERSIFIER_LENGTH]);
parser_error_t computePkd(const uint8_t ivk[KEY_LENGTH], const uint8_t diversifier[DIVERSIFIER_LENGTH], uint8_t pk_d[KEY_LENGTH]);
parser_error_t computeValueCommitment(uint64_t value, uint8_t *rcv, uint8_t *identifier, uint8_t *cv);
parser_error_t computeRk(keys_t *keys, uint8_t *alpha, uint8_t *rk);
parser_error_t crypto_encodeLargeBech32( const uint8_t *address, size_t addressLen, uint8_t *output, size_t outputLen, bool paymentAddr);
parser_error_t crypto_encodeAltAddress(const AddressAlt *addr, char *address, uint16_t addressLen);
parser_error_t derive_asset_type(const masp_asset_data_t *asset_data, uint8_t *identifier, uint8_t *nonce);
parser_error_t h_star(uint8_t *a, uint16_t a_len, uint8_t *b, uint16_t b_len, uint8_t *output);
parser_error_t parser_scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);
parser_error_t parser_compute_sbar(const uint8_t s[32], uint8_t r[32], uint8_t rsk[32], uint8_t sbar[32]);
parser_error_t parser_randomized_secret_from_seed(const uint8_t ask[32], const uint8_t alpha[32], uint8_t output[32]);
parser_error_t computeConvertValueCommitment(uint64_t value, uint8_t *rcv, uint8_t *generator, uint8_t *cv);
#ifdef __cplusplus
}
#endif
