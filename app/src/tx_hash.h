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

#include <stdint.h>
#include "zxerror.h"
#include "parser_txdef.h"

#define HASH_SIZE 32
#define PERSONALIZATION_SIZE 16

#define ZCASH_HEADERS_HASH_PERSONALIZATION "ZTxIdHeadersHash"
#define ZCASH_INPUTS_HASH_PERSONALIZATION "ZTxIdInputs_Hash"
#define ZCASH_OUTPUTS_HASH_PERSONALIZATION "ZTxIdOutputsHash"
#define ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION "ZTxIdSSpendsHash"
#define ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION "ZTxIdSSpendCHash"
#define ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION "ZTxIdSSpendNHash"
#define ZCASH_SAPLING_CONVERTS_HASH_PERSONALIZATION "ZTxIdConvertHash"
#define ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION "ZTxIdSOutputHash"
#define ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION "ZTxIdSOutC__Hash"
#define ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION "ZTxIdSOutM__Hash"
#define ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION "ZTxIdSOutN__Hash"
#define ZCASH_SAPLING_HASH_PERSONALIZATION "ZTxIdSaplingHash"
#define ZCASH_TRANSPARENT_HASH_PERSONALIZATION "ZTxIdTranspaHash"
#define ZCASH_TX_PERSONALIZATION_PREFIX "ZcashTxHash_"

zxerr_t tx_hash_header_data(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_transparent_inputs(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_transparent_outputs(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_sapling_spends(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_sapling_converts(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_sapling_outputs(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_sapling_data(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_transparent_data(const parser_tx_t *txObj, uint8_t *output);
zxerr_t tx_hash_txId(const parser_tx_t *txObj, uint8_t *output);
