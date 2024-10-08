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

#define MASPV5_TX_VERSION 0x02
#define MASPV5_VERSION_GROUP_ID 0x26A7270A
#define BRANCH_ID_IDENTIFIER 0xE9FF75A6
#define DEFAULT_IDENTIFIER {156, 229, 191, 54, 209, 138, 169, 235, 234, 174, 120, 186, 142, 34, 183, 118, 64, 243, 100, 134, 234, 27, 248, 27, 36, 245, 9, 146, 30, 110, 203, 169}

parser_error_t readMaspTx(parser_context_t *ctx, masp_tx_section_t *maspTx);
parser_error_t readMaspBuilder(parser_context_t *ctx, masp_builder_section_t *maspBuilder);
parser_error_t getSpendDescriptionLen(const uint8_t *spend, uint16_t *len);
parser_error_t getNextSpendDescription(parser_context_t *spend, uint8_t index);
parser_error_t getNextOutputDescription(parser_context_t *output, uint8_t index);
parser_error_t getNextConvertDescription(parser_context_t *convert, uint8_t index);
#ifdef __cplusplus
}
#endif
