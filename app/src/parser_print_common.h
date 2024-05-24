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

parser_error_t printMemo( const parser_context_t *ctx,
                        char *outKey, uint16_t outKeyLen,
                        char *outVal, uint16_t outValLen,
                        uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printExpert(const parser_context_t *ctx,
                           uint8_t displayIdx,
                           char *outKey, uint16_t outKeyLen,
                           char *outVal, uint16_t outValLen,
                           uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printCodeHash(section_t *codeSection,
                             char *outKey, uint16_t outKeyLen,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printAddressAlt(const AddressAlt *addr,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printAmount( const bytes_t *amount, bool isSigned, uint8_t amountDenom, const char* symbol,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printPublicKey(const bytes_t *pubkey,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount);

parser_error_t joinStrings(const bytes_t first, const bytes_t second, const char *separator,
                            char * outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printProposal( const tx_init_proposal_t *initProposal, uint8_t displayIdx,
                                   char *outKey, uint16_t outKeyLen,
                                   char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
