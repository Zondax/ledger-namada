/*******************************************************************************
 *   (c) 2018 -2024 Zondax AG
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

#include "signhash.h"
#include "cx.h"
#include <zxformat.h>
#include <zxmacros.h>
#include "tx_hash.h"

const uint8_t CONSENSUS_BRANCH_ID[4] = {0xa6, 0x75, 0xff, 0xe9}; // value from masp

// From https://github.com/anoma/masp/blob/main/masp_primitives/src/transaction/txid.rs#L297
zxerr_t signature_hash(const parser_tx_t *txObj, uint8_t *output) {
  zemu_log_stack("signature_hash");
  if (txObj == NULL || output == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t ctx = {0};

  uint8_t personalization[16] = "ZcashTxHash_";
  MEMCPY(personalization + 12, CONSENSUS_BRANCH_ID, 4);
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)personalization, PERSONALIZATION_SIZE));

  uint8_t header_digest[32] = {0};
  uint8_t transparent_digest[32] = {0};
  uint8_t sapling_digest[32] = {0};

  CHECK_ZXERR(tx_hash_header_data(txObj, header_digest));
  CHECK_ZXERR(tx_hash_transparent_data(txObj, transparent_digest));
  CHECK_ZXERR(tx_hash_sapling_data(txObj, sapling_digest));

  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, header_digest, HASH_SIZE, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, transparent_digest, HASH_SIZE, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, sapling_digest, HASH_SIZE, output, HASH_SIZE));

  return zxerr_ok;
}
