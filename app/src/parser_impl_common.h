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

#define BOND_NORMAL_PARAMS  3
#define BOND_EXPERT_PARAMS  8

#define TRANSFER_NORMAL_PARAMS  4
#define TRANSFER_EXPERT_PARAMS  9

#define INIT_ACCOUNT_NORMAL_PARAMS  2
#define INIT_ACCOUNT_EXPERT_PARAMS  7

#define WITHDRAW_NORMAL_PARAMS  2
#define WITHDRAW_EXPERT_PARAMS  7

#define INIT_VALIDATOR_NORMAL_PARAMS  8
#define INIT_VALIDATOR_EXPERT_PARAMS  13

parser_error_t readByte(parser_context_t *ctx, uint8_t *byte);
parser_error_t readBytes(parser_context_t *ctx, const uint8_t **output, uint16_t outputLen);
parser_error_t readUint16(parser_context_t *ctx, uint16_t *value);
parser_error_t readUint32(parser_context_t *ctx, uint32_t *value);
parser_error_t readUint64(parser_context_t *ctx, uint64_t *value);
parser_error_t readFieldSize(parser_context_t *ctx, uint32_t *size);
parser_error_t checkTag(parser_context_t *ctx, uint8_t expectedTag);

parser_error_t readToken(const bytes_t *token, const char **symbol);
parser_error_t readAddress(bytes_t pubkeyHash, char *address, uint16_t addressLen);

parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v);
parser_error_t readSections(parser_context_t *ctx, parser_tx_t *v);
parser_error_t readTimestamp(parser_context_t *ctx, bytes_t *timestamp);
parser_error_t validateTransactionParams(parser_tx_t *txObj);

#ifdef __cplusplus
}
#endif