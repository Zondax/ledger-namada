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
#if(0)
    InitProposal,
#endif
    VoteProposal,
    InitValidator,
    RevealPubkey,
    UpdateVP,
    Custom,
    Withdraw,
    Unknown,
} transaction_type_e;

typedef enum {
    Yay = 0,
    Nay = 1
} proposal_vote_e;

// Structure to match the Rust serialized Decimal format
typedef struct {
    int64_t num;
    uint32_t scale;
} serialized_decimal;

typedef struct {
    const uint8_t *ptr;
    uint32_t len;
} bytes_t;

typedef struct {
    uint8_t *ptr;
    uint32_t len;
} mut_bytes_t;

typedef struct {
    bytes_t title;
    bytes_t authors;
    bytes_t discussions_to;
    bytes_t created;
    bytes_t license;
    bytes_t abstract;
    bytes_t motivation;
    bytes_t details;
    bytes_t require;
} proposal_content_t;

typedef struct {
    uint8_t has_id;
    bytes_t proposal_id;
    proposal_content_t content;
    bytes_t author;
    // uint8_t proposal_type; // rust enum
    uint64_t voting_start_epoch;
    uint64_t voting_end_epoch;
    uint64_t grace_epoch;
    bytes_t proposal_code;
} tx_init_proposal_t;

typedef struct {
    uint64_t proposal_id;
    proposal_vote_e proposal_vote;
    // proposal author address
    bytes_t voter;
    // Delegator addresses
    uint32_t number_of_delegations;
    bytes_t delegations;
} tx_vote_proposal_t;

typedef struct {
    bytes_t pubkey;
    bytes_t vp_type_hash;
    const char* vp_type_text;
} tx_init_account_t;

typedef struct {
    bytes_t validator;
    uint64_t amount;
    uint8_t has_source;
    bytes_t source;
} tx_bond_t;

typedef struct {} tx_custom_t;

typedef struct {
    bytes_t pubkey;
} tx_reveal_pubkey_t;

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
    serialized_decimal commission_rate;
    serialized_decimal max_commission_rate_change;
    bytes_t vp_type_hash;
    const char* vp_type_text;
} tx_init_validator_t;

typedef struct {
    bytes_t address;
    bytes_t vp_type_hash;
    const char* vp_type_text;
} tx_update_vp_t;

typedef struct {
    bytes_t source_address;
    bytes_t target_address;
    // Transferred token address
    bytes_t token;
    uint8_t has_sub_prefix;
    bytes_t sub_prefix;
    uint64_t amount;
    const char* symbol;
    uint8_t has_key;
    bytes_t key;
    uint8_t has_shielded_hash;
    bytes_t shielded_hash;
} tx_transfer_t;

typedef struct {
    bytes_t address;
    uint64_t amount;
} fees_t;


#ifdef __cplusplus
}
#endif
