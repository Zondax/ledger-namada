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

spendlist_t NV_CONST N_spendlist_impl __attribute__((aligned(64)));
#define N_spendlist (*(NV_VOLATILE spendlist_t *)PIC(&N_spendlist_impl))

outputlist_t NV_CONST N_outputlist_impl __attribute__((aligned(64)));
#define N_outputlist (*(NV_VOLATILE outputlist_t *)PIC(&N_outputlist_impl))

convertlist_t NV_CONST N_convertlist_impl __attribute__((aligned(64)));
#define N_convertlist (*(NV_VOLATILE convertlist_t *)PIC(&N_convertlist_impl))

transaction_header_t transaction_header;

zxerr_t spend_append_rand_item(uint8_t *rcv, uint8_t *alpha) {
  if (transaction_header.spendlist_len >= SPEND_LIST_SIZE) {
    return zxerr_unknown;
  }
  spend_item_t newitem;
  MEMCPY(newitem.rcv, rcv, RANDOM_LEN);
  MEMCPY(newitem.alpha, alpha, RANDOM_LEN);

  MEMCPY_NV((void *)&N_spendlist.items[transaction_header.spendlist_len],
            &newitem, sizeof(spend_item_t));

  transaction_header.spendlist_len += 1;
  return zxerr_ok;
}

spend_item_t *spendlist_retrieve_rand_item(uint8_t i) {
  if (transaction_header.spendlist_len < i) {
    return NULL;
  } else {
    return (spend_item_t *)&N_spendlist.items[i];
  }
}

zxerr_t output_append_rand_item(uint8_t *rcv, uint8_t *rcm) {
  if (transaction_header.outputlist_len >= SPEND_LIST_SIZE) {
    return zxerr_unknown;
  }

  output_item_t newitem = {0};
  MEMCPY(newitem.rcv, rcv, RANDOM_LEN);
  MEMCPY(newitem.rcm, rcm, RANDOM_LEN);

  MEMCPY_NV((void *)&N_outputlist.items[transaction_header.outputlist_len],
            &newitem, sizeof(output_item_t));

  transaction_header.outputlist_len += 1;
  return zxerr_ok;
}

output_item_t *outputlist_retrieve_rand_item(uint64_t i) {
  if (transaction_header.outputlist_len <= i) {
    return NULL;
  } else {
    return (output_item_t *)&N_outputlist.items[i];
  }
}

zxerr_t convert_append_rand_item(uint8_t *rcv) {
  if (transaction_header.convertlist_len >= SPEND_LIST_SIZE) {
    return zxerr_unknown;
  }

  convert_item_t newitem = {0};
  MEMCPY(newitem.rcv, rcv, RANDOM_LEN);

  MEMCPY_NV((void *)&N_convertlist.items[transaction_header.convertlist_len],
            &newitem, sizeof(convert_item_t));

  transaction_header.convertlist_len += 1;
  return zxerr_ok;
}

convert_item_t *convertlist_retrieve_rand_item(uint8_t i) {
  if (transaction_header.convertlist_len <= i) {
    return NULL;
  } else {
    return (convert_item_t *)&N_convertlist.items[i];
  }
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
  return transaction_header.spends_sign_index < transaction_header.spends_sign_len;
}

zxerr_t spend_signatures_append(uint8_t *signature) {
  if (transaction_header.spends_sign_len >=
      transaction_header.spendlist_len) {
    return zxerr_unknown;
  }

  MEMCPY_NV((void *)&N_transactioninfo
                .spend_signatures[transaction_header.spends_sign_len],
            signature, SIGNATURE_SIZE);
  transaction_header.spends_sign_len++;
  return zxerr_ok;
}

zxerr_t get_next_spend_signature(uint8_t *result) {
  if (!spend_signatures_more_extract()) {
      return zxerr_unknown;
  }
  const uint8_t index = transaction_header.spends_sign_index;
  MEMCPY(result, (void *)&N_transactioninfo.spend_signatures[index], SIGNATURE_SIZE);
  transaction_header.spends_sign_index++;
  set_state(STATE_EXTRACT_SPENDS);
  return zxerr_ok;
}

uint8_t get_state() {
    return transaction_header.state;
}

void set_state(uint8_t state) {
    transaction_header.state = state;
}

void state_reset() {
    transaction_header.state = STATE_INITIAL;
}

void zeroize_signatures() {
  uint8_t sig[SIGNATURE_SIZE] = {0};

  transaction_header.spends_sign_len = 0;
  for (int i = 0; i < SPEND_LIST_SIZE; i++) {
    spend_signatures_append(sig);
  }
  transaction_header.spends_sign_len = 0;
  transaction_header.spends_sign_index = 0;
}

void zeroize_spends() {
  uint8_t rcv[RANDOM_LEN] = {0};
  uint8_t alpha[RANDOM_LEN] = {0};

  transaction_header.spendlist_len = 0;
  for (int i = 0; i < SPEND_LIST_SIZE; i++) {
    spend_append_rand_item(rcv, alpha);
  }
  transaction_header.spendlist_len = 0;
}

void zeroize_outputs() {
  uint8_t rcv[RANDOM_LEN] = {0};
  uint8_t rcm[RANDOM_LEN] = {0};

  transaction_header.outputlist_len = 0;
  for (int i = 0; i < SPEND_LIST_SIZE; i++) {
    output_append_rand_item(rcv, rcm);
  }
  transaction_header.outputlist_len = 0;
}

void zeroize_converts() {
  uint8_t rcv[RANDOM_LEN] = {0};

  transaction_header.convertlist_len = 0;
  for (int i = 0; i < SPEND_LIST_SIZE; i++) {
    convert_append_rand_item(rcv);
  }
  transaction_header.convertlist_len = 0;
}

void transaction_reset() {
    MEMZERO(&transaction_header, sizeof(transaction_header_t));
    zeroize_spends();
    zeroize_outputs();
    zeroize_converts();
    zeroize_signatures();
    set_state(STATE_INITIAL);
}

