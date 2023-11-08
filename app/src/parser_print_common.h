/*******************************************************************************
*  (c) 2018 - 2022 Zondax AG
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

#include "parser_common.h"
#include <zxmacros.h>
#include "zxtypes.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t printTxnFields(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printExpert(const parser_context_t *ctx,
                           uint8_t displayIdx,
                           char *outKey, uint16_t outKeyLen,
                           char *outVal, uint16_t outValLen,
                           uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printCodeHash(bytes_t *codeHash,
                             char *outKey, uint16_t outKeyLen,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printAddress(bytes_t pubkeyHash,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printCouncilVote(const council_t *councils,
                                char *outVal, uint16_t outValLen,
                                uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printAmount( const uint256_t *amount, uint8_t amountDenom, const char* symbol,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printVPTypeHash(bytes_t *codeHash,
                               char *outVal, uint16_t outValLen,
                               uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printPublicKey(const bytes_t *pubkey,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount);

parser_error_t uint256_to_str(char *output, uint16_t outputLen, const uint256_t *value);

#ifdef __cplusplus
}
#endif
