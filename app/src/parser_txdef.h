/*******************************************************************************
*  (c) 2018 - 2024 Zondax AG
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
#define OFFSET_INS 1
#define ASSET_ID_LEN 32
#define ANCHOR_LEN 32
#define SHIELDED_OUTPUTS_LEN 788
#define INT_128_LEN 16
#define ZKPROFF_LEN 192
#define AUTH_SIG_LEN 64
#define SHIELDED_SPENDS_LEN 96
#define SHIELDED_CONVERTS_LEN 32
#define TXIN_AUTH_LEN 60
#define TXOUT_AUTH_LEN 60
#define ESTABLISHED_ADDR_LEN 20
#define IMPLICIT_ADDR_LEN 20
// depth (1 byte) + parent FVK (4 bytes) + child index (4 bytes) + chain code (32 bytes) + fvk (32 bytes) + nullifier deriving key (32 bytes) + outgoing viewing key (32 bytes) + diversifier key (32 bytes)
#define EXTENDED_FVK_LEN 169
// note asset type (32 bytes) + note value (8 bytes) + note g_d (32 bytes) + note pk_d (32 bytes) + note rseed (1 byte + 32 bytes)
#define NOTE_LEN 137
#define OUT_NOTE_LEN 32 + 8 + 32 + 32
#define DIVERSIFIER_LEN 11
#define ALPHA_LEN 32
#define MEMO_LEN 512
#define PAYMENT_ADDR_LEN 32
#define OVK_LEN 32
#define VOUT_LEN 60
#define VIN_LEN 60
#define CV_LEN 32
#define NULLIFIER_LEN 32
#define RK_LEN 32
#define CMU_LEN 32
#define EPK_LEN 32
#define ENC_CIPHER_LEN 612
#define OUT_CIPHER_LEN 80
#define COMPACT_NOTE_SIZE 84
#define NOTE_PLAINTEXT_SIZE 512
#define POSITION_LEN 8
#define RANDOM_LEN 32
#define IDENTIFIER_LEN 32
#define TAG_LEN 1

#define CMU_OFFSET CV_LEN
#define EPK_OFFSET CMU_OFFSET + CMU_LEN
#define ENC_CIPHER_OFFSET EPK_OFFSET + EPK_LEN
#define OUT_CIPHER_OFFSET ENC_CIPHER_OFFSET + ENC_CIPHER_LEN
#define ALPHA_OFFSET EXTENDED_FVK_LEN + DIVERSIFIER_LEN + NOTE_LEN

#define VIN_VALUE_OFFSET ASSET_ID_LEN
#define VIN_ADDR_OFFSET VIN_VALUE_OFFSET + 8

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
typedef struct {
    bytes_t salt;
    uint8_t idx;
    concatenated_hashes_t hashes;
    signer_discriminant_e signerDiscriminant;
    AddressAlt address;
    bytes_t addressBytes;
    uint32_t pubKeysLen;
    bytes_t pubKeys;
    uint32_t signaturesLen;
    bytes_t indexedSignatures;
} signature_section_t;
typedef struct {
    AddressAlt token;
    uint8_t denom;
    uint8_t position;
    uint8_t has_epoch;
    uint64_t epoch;
    bytes_t bytes;
} masp_asset_data_t;

typedef struct {
    bytes_t asset_type_id; // [u8;32]
    uint64_t value;
    bytes_t transparent_address; // [u8;20]
} masp_asset_type_t;
typedef struct {
    uint64_t n_shielded_spends;
    uint64_t n_shielded_converts;
    uint64_t n_shielded_outputs;
    bytes_t shielded_spends; // [u8;96]
    bytes_t shielded_converts; // [u8;32]
    bytes_t shielded_outputs; // [u8;788]

    uint64_t n_value_sum_asset_type;
    bytes_t value_sum_asset_type; // [u8; 32] + 8 bytes

    bytes_t anchor_shielded_spends; // 32 bytes: bls12_381::Scalar
    bytes_t anchor_shielded_converts; // 32 bytes: bls12_381::Scalar

    bytes_t zkproof_shielded_spends;  // [u8; GROTH_PROOF_SIZE] where GROTH_PROOF_SSIZE = 48 + 96 + 48 = 192
    bytes_t auth_sig_shielded_spends; // 64 bytes:    rbar: [u8; 32], sbar: [u8; 32],
    bytes_t zkproof_shielded_converts;  // [u8; GROTH_PROOF_SIZE] where GROTH_PROOF_SSIZE = 48 + 96 + 48 = 192
    bytes_t zkproof_shielded_outputs;  // [u8; GROTH_PROOF_SIZE] where GROTH_PROOF_SSIZE = 48 + 96 + 48 = 192

    bytes_t authorization; // 64 bytes: rbar: [u8; 32], sbar: [u8; 32],
} masp_sapling_bundle_t;

typedef struct {
    uint8_t cv[CV_LEN];
    uint8_t nullifier[NULLIFIER_LEN];
    uint8_t rk[RK_LEN];
} shielded_spends_t;

typedef struct {
    uint8_t cv[CV_LEN];
    uint8_t cmu[CMU_LEN];
    uint8_t ephemeral_key[EPK_LEN];
    uint8_t enc_ciphertext[ENC_CIPHER_LEN];
    uint8_t out_ciphertext[OUT_CIPHER_LEN];
} shielded_outputs_t;

typedef struct {
    uint64_t n_vin;
    bytes_t vin; // [u8;60]
    uint64_t n_vout;
    bytes_t vout; // [u8;60]
} masp_transparent_bundle_t;

// For masp TxData definition, see:
// https://github.com/anoma/masp/blob/0d7dc07d24b878e9162c25260ed744265dd2f748/masp_primitives/src/transaction.rs#L189-L190
typedef struct {
    uint32_t tx_version;
    uint32_t version_group_id;
    uint32_t consensus_branch_id;
    uint32_t lock_time;
    uint32_t expiry_height;
    uint16_t has_transparent_bundle;
    masp_transparent_bundle_t transparent_bundle;
    uint16_t has_sapling_bundle;
    masp_sapling_bundle_t sapling_bundle;
} masp_tx_data_t;

typedef struct {
    bytes_t tx_id; // [u8;32]
    masp_tx_data_t data;
    const uint8_t* masptx_ptr;
    uint64_t masptx_len;
} masp_tx_section_t;

typedef struct {
    uint32_t n_spends_indices;
    uint32_t n_converts_indices;
    uint32_t n_outputs_indices;
    bytes_t spends_indices;
    bytes_t converts_indices;
    bytes_t outputs_indices;
} masp_sapling_metadata_t;

typedef struct{
    uint32_t n_inputs;
    bytes_t inputs; // [u8;60]
    uint32_t n_vout;
    bytes_t vout; // [u8;60]
}masp_transparent_builder_t;

typedef struct{
    uint8_t has_spend_anchor;
    bytes_t spend_anchor; // [u8;32]
    uint32_t target_height;
    uint64_t n_value_sum_asset_type;
    bytes_t value_sum_asset_type; // [u8; 32] + 8 bytes
    uint8_t has_convert_anchor;
    bytes_t convert_anchor; // [u8;32]
    uint8_t has_ovk;

    uint32_t n_spends;
    uint32_t n_converts;
    uint32_t n_outputs;
    bytes_t spends;
    bytes_t converts;
    bytes_t outputs;
}masp_sapling_builder_t;

typedef struct {
    uint32_t target_height;
    uint32_t expiry_height;
    masp_transparent_builder_t transparent_builder;
    masp_sapling_builder_t sapling_builder;
} masp_builder_t;

typedef struct {
    bytes_t target_hash;
    uint32_t n_asset_type;
    bytes_t asset_data;
    masp_sapling_metadata_t metadata;
    masp_builder_t builder;
} masp_builder_section_t;

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
    section_t ciphertext; // todo: if we need to parse this in future, it will not be a section_t
    masp_tx_section_t maspTx;
    masp_builder_section_t maspBuilder;
} sections_t;

typedef struct {
    bytes_t timestamp;
    header_t header;
    sections_t sections;
    uint8_t maspTx_idx;
    bool isMasp;
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
