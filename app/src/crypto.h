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

#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include "zxerror.h"
#include "parser_txdef.h"

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

zxerr_t crypto_fillAddress(signing_key_type_e addressKind, uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen);
zxerr_t crypto_extractPublicKey_ed25519(uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_extractPublicKey_secp256k1(uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_sign_ed25519(uint8_t *signature, uint16_t signatureMaxLen, const uint8_t *message, uint16_t messageLen);

zxerr_t crypto_sign_secp256k1(uint8_t *signature,
                              uint16_t signatureMaxLen,
                              uint16_t *sigSize);

zxerr_t crypto_hashHeader(const header_t *header, uint8_t *output, uint32_t outputLen);
zxerr_t crypto_hashDataSection(const section_t *data, uint8_t *output, uint32_t outputLen);
zxerr_t crypto_hashCodeSection(const section_t *section, uint8_t *output, uint32_t outputLen);

zxerr_t crypto_signHeader(const header_t *header, const bytes_t *pubkey);
zxerr_t crypto_signDataSection(const section_t *data, const bytes_t *pubkey);
zxerr_t crypto_signCodeSection(const section_t *code, const bytes_t *pubkey);
zxerr_t crypto_getSignature(uint8_t *output, uint16_t outputLen, uint8_t slot);

#ifdef __cplusplus
}
#endif
