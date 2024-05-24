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

#include "nvdata.h"
#include "coin.h"
#include "constants.h"
#include "cx.h"
#include "os.h"
#include "view.h"

transaction_info_t NV_CONST N_transaction_info_impl
    __attribute__((aligned(64)));
#define N_transactioninfo                                                      \
  (*(NV_VOLATILE transaction_info_t *)PIC(&N_transaction_info_impl))

transaction_header_t transaction_header;

zxerr_t transaction_add(masp_type_e type) {
    switch(type) {
        case spend:
        transaction_header.spendlist_len++;
            break;
        case output:
        transaction_header.outputlist_len++;
            break;
        case convert:
        transaction_header.convertlist_len++;
            break;
        default:
            return zxerr_unknown;
    }
    return zxerr_ok;
}

uint8_t transaction_get_n_spends() {
    return transaction_header.spendlist_len;
}

uint8_t transaction_get_n_outputs() {
    return transaction_header.outputlist_len;
}

uint8_t transaction_get_n_converts() {
    return transaction_header.convertlist_len;
}

bool spend_signatures_more_extract() {
  return transaction_header.spends_sign_index > 0;
}

zxerr_t spend_signatures_append(uint8_t *signature) {
  if (transaction_header.spends_sign_index >=
      transaction_header.spendlist_len) {
    return zxerr_unknown;
  }

  MEMCPY_NV((void *)&N_transactioninfo
                .spend_signatures[transaction_header.spends_sign_index],
            signature, SIGNATURE_SIZE);
  transaction_header.spends_sign_index++;
  return zxerr_ok;
}

zxerr_t get_next_spend_signature(uint8_t *result) {
  const uint8_t index = transaction_header.spendlist_len - transaction_header.spends_sign_index;
  if (index >= transaction_header.spendlist_len) {
    return zxerr_unknown;
  }
  MEMCPY(result, (void *)&N_transactioninfo.spend_signatures[index], SIGNATURE_SIZE);
  transaction_header.spends_sign_index--;
  if (!spend_signatures_more_extract()) {
    transaction_reset();
  }
  return zxerr_ok;
}

void zeroize_signatures() {
  uint8_t sig[SIGNATURE_SIZE] = {0};

  transaction_header.spends_sign_index = 0;
  for (int i = 0; i < SPEND_LIST_SIZE; i++) {
    spend_signatures_append(sig);
  }
  transaction_header.spends_sign_index = 0;
}

void transaction_reset() {
    MEMZERO(&transaction_header, sizeof(transaction_header_t));
    zeroize_signatures();
}

