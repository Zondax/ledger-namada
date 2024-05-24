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

#define SPEND_LIST_SIZE 15
#define SIGNATURE_SIZE 64

typedef struct {
  uint8_t spendlist_len;
  uint8_t outputlist_len;
  uint8_t convertlist_len;
  uint8_t spends_sign_index;
} transaction_header_t;

typedef struct {
  uint8_t spend_signatures[SPEND_LIST_SIZE][64];
} transaction_info_t;

zxerr_t transaction_add(masp_type_e type);

void transaction_reset();
uint8_t transaction_get_n_spends();
uint8_t transaction_get_n_outputs();
uint8_t transaction_get_n_converts();
zxerr_t get_next_spend_signature(uint8_t *result);
zxerr_t spend_signatures_append(uint8_t *signature);
bool spend_signatures_more_extract();
