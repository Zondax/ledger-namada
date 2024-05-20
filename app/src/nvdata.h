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

#define SPEND_LIST_SIZE 5
#define SIGNATURE_SIZE 64

typedef struct {
  uint8_t rcv[32];
  uint8_t alpha[32];
} spend_item_t;

typedef struct {
  uint8_t rcv[32];
} convert_item_t;

typedef struct {
  uint8_t rcv[32];
  uint8_t rcm[32];
} output_item_t;

typedef struct {
  uint8_t n_spends;
  uint8_t n_outputs;
  uint8_t n_converts;

  spend_item_t spends[SPEND_LIST_SIZE];
  output_item_t outputs[SPEND_LIST_SIZE];
  convert_item_t converts[SPEND_LIST_SIZE];
} transaction_info_t;


zxerr_t transaction_add_sizes(uint8_t n_spends, uint8_t n_outputs,
                                 uint8_t n_converts);
zxerr_t transaction_append_spend_rcv(uint8_t i, uint8_t *rcv);
zxerr_t transaction_append_spend_alpha(uint8_t i, uint8_t *alpha);
zxerr_t transaction_append_output_rcv(uint8_t i, uint8_t *rcv);
zxerr_t transaction_append_output_rcm(uint8_t i, uint8_t *rcm);
zxerr_t transaction_append_convert_rcv(uint8_t i, uint8_t *rcv);
void transaction_reset();
uint8_t transaction_get_n_spends();
uint8_t transaction_get_n_outputs();
uint8_t transaction_get_n_converts();
uint8_t *transaction_get_spend_rcv(uint8_t i);
uint8_t *transaction_get_spend_alpha(uint8_t i);
uint8_t *transaction_get_output_rcv(uint8_t i);
uint8_t *transaction_get_output_rcm(uint8_t i);
uint8_t *transaction_get_convert_rcv(uint8_t i);
