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

typedef enum {
    Bond = 0,
    Unbond,
    Transfer,
    InitAccount,
    InitProposal,
    VoteProposal,
    BecomeValidator,
    RevealPubkey,
    UpdateVP,
    Custom,
    Withdraw,
    CommissionChange,
    IBC,
    UnjailValidator,
    DeactivateValidator,
    ReactivateValidator,
    Redelegate,
    ClaimRewards,
    ResignSteward,
    ChangeConsensusKey,
    UpdateStewardCommission,
    ChangeValidatorMetadata,
    BridgePoolTransfer,
} transaction_type_e;

typedef enum {
    Yay = 0,
    Nay = 1,
    Abstain = 2
} proposal_vote_e;

typedef enum {
    Default = 0,
    DefaultWithWasm = 1,
    PGFSteward = 2,
    PGFPayment = 3,
} yay_vote_type_e;

typedef enum {
    Continuous = 0,
    Retro = 1,
} pgf_action_e;

typedef enum {
    Add = 0,
    Remove = 1,
} pgf_continuous_type_e;

typedef enum {
    PGFTargetInternal = 0,
    PGFTargetIBC = 1,
} pgf_target_type_e;

typedef enum {
    Erc20 = 0,
    Nut = 1,
} transfer_to_ethereum_kind_e;

// Structure to match the Rust serialized Decimal format
typedef struct {
    int64_t num;
    uint32_t scale;
} serialized_decimal;

typedef struct {
    const uint8_t *ptr;
    uint16_t len;
} bytes_t;

typedef struct {
    uint8_t *ptr;
    uint32_t len;
} mut_bytes_t;

typedef struct {
    bytes_t address;
    bytes_t amount;
} pgf_internal_t;

typedef struct {
    bytes_t target;
    bytes_t amount;
    bytes_t portId;
    bytes_t channelId;
} pgf_ibc_t;
typedef struct {
    pgf_action_e action;
    pgf_continuous_type_e add_rem;
    pgf_target_type_e targetType;
    union {
        pgf_internal_t internal;
        pgf_ibc_t ibc;
    };
    uint16_t length;
} pgf_payment_action_t;

typedef struct {
    bytes_t content_hash;
    bytes_t content_sechash;
    bytes_t author;
    uint64_t voting_start_epoch;
    uint64_t voting_end_epoch;
    uint64_t activation_epoch;
    uint8_t proposal_type;
    union {
        struct {
            bytes_t proposal_code_sechash;
            bytes_t proposal_code_hash;
        };
        struct {
            uint32_t pgf_steward_actions_num;
            bytes_t pgf_steward_actions;
        };
        struct {
            uint32_t pgf_payment_actions_num;
            uint32_t pgf_payment_ibc_num;
            bytes_t pgf_payment_actions;
        };
    };

    uint8_t content_secidx;
    uint8_t proposal_code_secidx;
} tx_init_proposal_t;


typedef struct {
    uint64_t millis;
    uint32_t nanos;
} timestamp_t;

typedef struct {
    bytes_t council_address;
    bytes_t amount;
} council_t;

typedef struct {
    uint64_t proposal_id;
    proposal_vote_e proposal_vote;
    uint32_t number_of_councils;
    bytes_t councils;
    bytes_t eth_bridge_signature;
    // proposal author address
    bytes_t voter;
    // Delegator addresses
    uint32_t number_of_delegations;
    bytes_t delegations;
} tx_vote_proposal_t;

typedef struct {
    uint32_t number_of_pubkeys;
    bytes_t pubkeys;
    uint8_t threshold;
    bytes_t vp_type_sechash;
    bytes_t vp_type_hash;
    uint8_t vp_type_secidx;
    const char* vp_type_text;
} tx_init_account_t;

typedef struct {
    bytes_t validator;
    bytes_t amount;
    uint8_t has_source;
    bytes_t source;
} tx_bond_t;

typedef struct {
    bytes_t src_validator;
    bytes_t dest_validator;
    bytes_t owner;
    bytes_t amount;
} tx_redelegation_t;

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
    bytes_t validator;
} tx_unjail_validator_t;

typedef tx_unjail_validator_t tx_activate_validator_t;

typedef struct {
    bytes_t validator;
    bytes_t new_rate;
} tx_commission_change_t;

typedef struct {
    bytes_t address;
    bytes_t consensus_key;
    bytes_t eth_cold_key;
    bytes_t eth_hot_key;
    bytes_t protocol_key;
    bytes_t commission_rate;
    bytes_t max_commission_rate_change;
    bytes_t email;
    bytes_t description;
    bytes_t website;
    bytes_t discord_handle;
    bytes_t avatar;
} tx_become_validator_t;

typedef struct {
    bytes_t address;
    uint32_t number_of_pubkeys;
    bytes_t pubkeys;
    uint8_t has_threshold;
    uint8_t threshold;
    uint8_t has_vp_code;
    bytes_t vp_type_sechash;
    bytes_t vp_type_hash;
    uint8_t vp_type_secidx;
    const char* vp_type_text;
} tx_update_vp_t;

typedef struct {
    bytes_t source_address;
    bytes_t target_address;
    // Transferred token address
    bytes_t token;
    uint8_t has_sub_prefix;
    bytes_t sub_prefix;
    bytes_t amount;
    uint8_t amount_denom;
    const char* symbol;
    uint8_t has_key;
    bytes_t key;
    uint8_t has_shielded_hash;
    bytes_t shielded_hash;
} tx_transfer_t;

typedef struct {
    bytes_t port_id;
    bytes_t channel_id;
    bytes_t token_address;
    bytes_t token_amount;
    bytes_t sender_address;
    bytes_t receiver;
    uint8_t timeout_height_type;
    uint64_t revision_number;
    uint64_t revision_height;
    timestamp_t timeout_timestamp;
} tx_ibc_t;

typedef struct {
    bytes_t steward;
} tx_resign_steward_t;

typedef struct {
    bytes_t validator;
    bytes_t consensus_key;
} tx_consensus_key_change_t;

typedef struct {
    bytes_t steward;
    uint32_t commissionLen;
    bytes_t commission;
} tx_update_steward_commission_t;

typedef struct {
    uint8_t kind;
    bytes_t asset;
    bytes_t recipient;
    bytes_t sender;
    bytes_t amount;

    bytes_t gasToken;
    bytes_t gasAmount;
    bytes_t gasPayer;
} tx_bridge_pool_transfer_t;

  typedef struct {
    bytes_t validator;
    bytes_t email;
    bytes_t description;
    bytes_t website;
    bytes_t discord_handle;
    bytes_t avatar;
    uint8_t has_commission_rate;
    bytes_t commission_rate;
  } tx_metadata_change_t;

typedef struct {
    bytes_t address;
    bytes_t amount;
    uint8_t denom;
    const char *symbol;
} fees_t;

#ifdef __cplusplus
}
#endif
