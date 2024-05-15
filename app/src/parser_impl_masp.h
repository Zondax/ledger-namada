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

#define MASPV5_TX_VERSION 0x02
#define MASPV5_VERSION_GROUP_ID 0x26A7270A
#define BRANCH_ID_IDENTIFIER 0xE9FF75A6

parser_error_t readMaspTx(parser_context_t *ctx, masp_tx_section_t *maspTx);
parser_error_t readMaspBuilder(parser_context_t *ctx, masp_builder_section_t *maspBuilder) ;
parser_error_t getSpendDescriptionLen(const uint8_t *spend, uint16_t *len);
parser_error_t getOutputDescriptionLen(const uint8_t *spend, uint16_t *len);
parser_error_t getConvertLen(const uint8_t *convert, uint64_t *len);
#ifdef __cplusplus
}
#endif
