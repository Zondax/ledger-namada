/*******************************************************************************
*  (c) 2018 - 2022 Zondax AG
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
} transaction_type_e;

typedef struct {
    uint64_t seconds;
    uint32_t nanos;
} prototimestamp_t;

typedef struct {
    const uint8_t *ptr;
    uint32_t len;
} bytes_t;

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
    // tx_t????
    bytes_t source;
    bytes_t target;
    bytes_t token;
    uint8_t has_sub_prefix;
    const char* sub_prefix;
    uint64_t amount;
} tx_transfer_t;

typedef struct {
    bytes_t code;
    bytes_t data;
    prototimestamp_t timestamp;

    const uint8_t *extra;
    uint32_t extraSize;

    uint8_t hasInnerTx;
    const uint8_t *innerTx;
    uint32_t innerTxSize;
} tx_t;


typedef struct {
    bytes_t address;
    uint64_t amount;
} fees_t;

typedef struct {
    const uint8_t *startData;

    bytes_t innerTxHash;
    fees_t fees;
    bytes_t pubkey;

    uint64_t epoch;
    uint64_t gasLimit;


    // tx_hash

    // solution???
} wrapperTx_t;

typedef struct {
    const uint8_t *code;
    uint32_t codeSize;

    const uint8_t *data;
    uint32_t dataSize;

    prototimestamp_t timestamp;
} outer_layer_tx_t;

typedef struct{
    transaction_type_e typeTx;
    tx_t innerTx;
    wrapperTx_t wrapperTx;
    union {
        tx_bond_t bond;
        tx_transfer_t transfer;
        tx_init_account_t initAccount;
        tx_withdraw_t withdraw;
        tx_init_validator_t initValidator;
    };

} parser_tx_t;


#ifdef __cplusplus
}
#endif
