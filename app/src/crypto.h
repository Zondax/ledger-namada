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

#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include "zxerror.h"
#include "parser_txdef.h"

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

zxerr_t crypto_fillAddress(signing_key_type_e addressKind, uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen);
zxerr_t crypto_sign(const parser_tx_t *txObj, uint8_t *output, uint16_t outputLen);
zxerr_t crypto_fillMASP(uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen, key_kind_e requestedKey);
zxerr_t crypto_sign_masp_spends(parser_tx_t *txObj, uint8_t *output, uint16_t outputLen);
zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen, uint16_t *cmdResponseLen);
zxerr_t crypto_computeRandomness(masp_type_e type, uint8_t *out, uint16_t outLen, uint16_t *replyLen);
#ifdef __cplusplus
}
#endif
