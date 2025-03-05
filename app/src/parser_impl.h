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

parser_error_t _read(parser_context_t *c, parser_tx_t *v);
parser_error_t getNumItems(const parser_context_t *ctx, uint8_t *numItems);
bool hasMemoToPrint(const parser_context_t *ctx);
parser_error_t checkMaspSpendsSymbols (const parser_context_t *ctx);
parser_error_t checkMaspOutputsSymbols (const parser_context_t *ctx);
parser_error_t findAssetData(const masp_builder_section_t *maspBuilder, const uint8_t *stoken, masp_asset_data_t *asset_data, uint32_t *index);
parser_error_t getSpendfromIndex(uint32_t index, bytes_t *spend);
parser_error_t getOutputfromIndex(uint32_t index, bytes_t *out);

#ifdef __cplusplus
}
#endif
