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
 #pragma once

#include "coin.h"
#include "constants.h"
#include "zxerror.h"
#include "zxmacros.h"
#include <stdbool.h>
#include "parser_txdef.h"

#define SPEND_LIST_SIZE 15
#define SIGNATURE_SIZE 64

// Possible states
#define STATE_INITIAL 0x00
#define STATE_PROCESSED_RANDOMNESS 0x01
#define STATE_SIGNED_SPENDS 0x02
#define STATE_EXTRACT_SPENDS 0x03

typedef struct {
  uint8_t rcv[RANDOM_LEN];
  uint8_t alpha[RANDOM_LEN];
} spend_item_t;

typedef struct {
  spend_item_t items[SPEND_LIST_SIZE];
} spendlist_t;

typedef struct {
  uint8_t rcv[RANDOM_LEN];
  uint8_t rcm[RANDOM_LEN];
} output_item_t;

typedef struct {
  output_item_t items[SPEND_LIST_SIZE];
} outputlist_t;
typedef struct {
  uint8_t rcv[RANDOM_LEN];
} convert_item_t;

typedef struct {
  convert_item_t items[SPEND_LIST_SIZE];
} convertlist_t;
typedef struct {
  uint8_t spendlist_len;
  uint8_t outputlist_len;
  uint8_t convertlist_len;
  uint8_t spends_sign_len;
  uint8_t spends_sign_index;
  uint8_t state;
} transaction_header_t;

typedef struct {
  uint8_t spend_signatures[SPEND_LIST_SIZE][64];
} transaction_info_t;

zxerr_t spend_append_rand_item(uint8_t *rcv, uint8_t *alpha);
spend_item_t *spendlist_retrieve_rand_item(uint8_t i);
zxerr_t output_append_rand_item(uint8_t *rcv, uint8_t *rcm);
output_item_t *outputlist_retrieve_rand_item(uint64_t i);
zxerr_t convert_append_rand_item(uint8_t *rcv);
convert_item_t *convertlist_retrieve_rand_item(uint8_t i);

void transaction_reset();
uint8_t transaction_get_n_spends();
uint8_t transaction_get_n_outputs();
uint8_t transaction_get_n_converts();
zxerr_t get_next_spend_signature(uint8_t *result);
zxerr_t spend_signatures_append(uint8_t *signature);
bool spend_signatures_more_extract();

uint8_t get_state();
void state_reset();
void set_state(uint8_t state);
