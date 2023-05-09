/*******************************************************************************
*  (c) 2018 - 2023 Zondax AG
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define TAG_CODE    0x0a
#define TAG_DATA    0x12
#define TAG_TS      0x1a
#define TAG_S       0x08
#define TAG_N       0x10
#define TAG_INNER_TX_HASH    0x22

#define SHA256_SIZE 32

typedef enum {
    Bond = 0,
    Unbond,
    Transfer,
    InitAccount,
    InitProposal,
    InitValidator,
    UpdateVP,
    Custom,
    Withdraw,
    Unknown,
} transaction_type_e;

typedef struct {
    const uint8_t *ptr;
    uint32_t len;
} bytes_t;

typedef struct {
    uint8_t *ptr;
    uint32_t len;
} mut_bytes_t;


typedef struct {
    bytes_t pubkey;
} tx_init_account_t;

typedef struct {
    bytes_t validator;
    uint64_t amount;
    uint8_t has_source;
    bytes_t source;
} tx_bond_t;
typedef struct {
    bytes_t validator;
    uint8_t has_source;
    bytes_t source;
} tx_withdraw_t;

typedef struct {
    bytes_t account_key;
    bytes_t consensus_key;
    bytes_t protocol_key;
    bytes_t dkg_key;
    // commission rate
    // max commission rate change
    // validator VP
} tx_init_validator_t;

typedef struct {
    bytes_t source;
    bytes_t target;
    bytes_t token;
    uint8_t has_sub_prefix;
    const char* sub_prefix;
    uint64_t amount;
    const char* symbol;
} tx_transfer_t;

typedef struct {
    bytes_t address;
    uint64_t amount;
} fees_t;


#ifdef __cplusplus
}
#endif
