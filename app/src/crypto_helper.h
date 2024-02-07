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

#include <stdint.h>
#include <stdbool.h>
#include "zxerror.h"
#include "parser_common.h"

#define CODE_HASH_SIZE  32
#define TIMESTAMP_SIZE  14

#define CODE_HASH_INFO_SIZE 2


uint8_t crypto_encodePubkey_ed25519(uint8_t *buffer, uint16_t bufferLen, const uint8_t *pubkey);

zxerr_t crypto_sha256(const uint8_t *input, uint16_t inputLen,
                      uint8_t *output, uint16_t outputLen);

zxerr_t crypto_computeCodeHash(section_t *extraData);
zxerr_t crypto_hashDataSection(const section_t *data, uint8_t *output, uint32_t outputLen);
zxerr_t crypto_hashCodeSection(const section_t *section, uint8_t *output, uint32_t outputLen);
zxerr_t crypto_hashExtraDataSection(const section_t *section, uint8_t *output, uint32_t outputLen);

#ifdef __cplusplus
}
#endif
