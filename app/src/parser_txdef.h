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
#include <stdbool.h>
#include "parser_types.h"
#include "coin.h"

#define MAX_EXTRA_DATA_SECS 4
#define MAX_SIGNATURE_SECS 3


typedef struct {
    uint8_t address[ADDRESS_LEN_TESTNET];
    const char *symbol;
} tokens_t;

typedef struct {
    const char tag[40];
    const char *text;
} vp_types_t;

typedef struct {
    const char tag[40];
    transaction_type_e type;
} txn_types_t;

typedef struct {
    uint32_t hashesLen;
    mut_bytes_t hashes;
    mut_bytes_t indices;
} concatenated_hashes_t;

typedef enum {
    Address = 0,
    PubKeys = 1
} signer_discriminant_e;
// -----------------------------------------------------------------
typedef struct {
    bytes_t salt;
    uint8_t idx;
    concatenated_hashes_t hashes;
    signer_discriminant_e signerDiscriminant;
    bytes_t address;
    uint32_t pubKeysLen;
    bytes_t pubKeys;
    uint32_t signaturesLen;
    bytes_t indexedSignatures;
} signature_section_t;
#if(0)
typedef struct {
    bytes_t cv; // 160 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32 bytes
    bytes_t anchor; // 32 bytes: bls12_381::Scalar
    bytes_t nullifier; // 32 bytes:  [u8; 32]
    bytes_t rk; // 160 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32
    bytes_t zkproof; // [u8; GROTH_PROOF_SIZE] where GROTH_PROOF_SSIZE = 48 + 96 + 48 = 192
    bytes_t spend_auth_sig; // 64 bytes:    rbar: [u8; 32], sbar: [u8; 32],
} spend_description_t; // 640 bytes

typedef struct {
    bytes_t cv; // 160 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32 bytes
    bytes_t cmu; // 32 bytes: bls12_381::Scalar
    bytes_t ephemeral_key; // 32 bytes:  [u8; 32]
} output_description_t; // 224 bytes

typedef struct {
    spend_description_t* shielded_spends;
    bytes_t shielded_converts;
    output_description_t* shielded_outputs;
    uint64_t value_balance;
    bytes_t authorization;
    // nothing? or (unauth) a Vec<TransparentInputInfo>
    // for shielded a redjubjub::Signature
} masp_sapling_bundle_t;


typedef struct{
    bytes_t asset_type_id; // [u8;32]
    uint8_t has_asset_type_nonce;
    uint8_t asset_type_nonce; // 1 byte
    int64_t value; // 8 bytes
    bytes_t transparent_address; // [u8;20]
    //bytes_t transparent_sig; // this seems to always be empty
} masp_vin_t;

// https://github.com/anoma/masp/blob/0d7dc07d24b878e9162c25260ed744265dd2f748/masp_primitives/src/transaction/components/transparent.rs#L32
typedef struct {
    bytes_t vin;
    bytes_t vout;
    bytes_t authorization; // nothing if Auth;  for unauth a Vec<TransparentInputInfo>
} masp_transparent_bundle_t;

// For masp TxData definition, see:
// https://github.com/anoma/masp/blob/0d7dc07d24b878e9162c25260ed744265dd2f748/masp_primitives/src/transaction.rs#L189-L190
typedef struct {
    uint32_t tx_version;
    uint32_t version_group_id;
    uint32_t consensus_branch_id; // this is an enum with at the moment only 0 -> MASP
    uint32_t lock_time;
    uint32_t expiry_height;
    uint8_t has_transparent_bundle;
    masp_transparent_bundle_t transparent_bundle;
    uint8_t has_sapling_bundle;
    masp_sapling_bundle_t sapling_bundle;
} masp_tx_data_t;

typedef struct {
    bytes_t tx_id; // [u8;32]
    masp_tx_data_t data;
} masp_tx_section_t;
#endif

typedef struct {
    uint8_t discriminant;
    bytes_t salt;
    uint8_t commitmentDiscriminant;
    bytes_t bytes;
    uint8_t bytes_hash[HASH_LEN];
    bytes_t tag;
    uint8_t idx;
} section_t;

typedef struct {
    bytes_t extBytes;
    bytes_t bytes;
    fees_t fees;
    bytes_t pubkey;
    uint64_t gasLimit;
    uint32_t batchLen;
    bytes_t dataHash;
    bytes_t codeHash;
    bytes_t memoHash;
    const section_t *memoSection;
    uint8_t atomic;
} header_t;
typedef struct {
    uint32_t sectionLen;
    uint32_t extraDataLen;
    uint32_t signaturesLen;
    section_t code;
    section_t data;
    section_t extraData[MAX_EXTRA_DATA_SECS];
    signature_section_t signatures[MAX_SIGNATURE_SECS];
#if(0)
    section_t ciphertext; // todo: if we need to parse this in future, it will not be a section_t
    masp_tx_section_t maspTx;
    section_t maspBuilder; // todo: if we need to parse this in future, it will not be a section_t
#endif
} sections_t;

typedef struct {
    bytes_t timestamp;
    header_t header;
    sections_t sections;
} transaction_t;


typedef struct{
    transaction_type_e typeTx;
    union {
        tx_bond_t bond;
        tx_custom_t custom;
        tx_transfer_t transfer;
        tx_init_account_t initAccount;
        tx_init_proposal_t initProposal;
        tx_vote_proposal_t voteProposal;
        tx_reveal_pubkey_t revealPubkey;
        tx_withdraw_t withdraw;
        tx_commission_change_t commissionChange;
        tx_update_vp_t updateVp;
        tx_ibc_t ibc;
        tx_unjail_validator_t unjailValidator;
        tx_become_validator_t becomeValidator;
        tx_activate_validator_t activateValidator;
        tx_redelegation_t redelegation;
        tx_resign_steward_t resignSteward;
        tx_consensus_key_change_t consensusKeyChange;
        tx_update_steward_commission_t updateStewardCommission;
        tx_metadata_change_t metadataChange;
        tx_bridge_pool_transfer_t bridgePoolTransfer;
    };

    transaction_t transaction;

} parser_tx_t;


#ifdef __cplusplus
}
#endif
