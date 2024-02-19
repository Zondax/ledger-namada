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
#endif

typedef struct {
  uint64_t lo;
  int64_t hi;
} int128_t;

typedef struct {
  uint64_t lo;
  uint64_t hi;
} uint128_t;

typedef struct {
  uint8_t identifier[32];
} AssetType;

typedef struct {
  AssetType f0;
  int128_t f1;
} AssetType_i128;

typedef struct {
  uint32_t f0;
} BlockHeight;

typedef struct {
  uint32_t tag;
  union {
  };
} BranchId;

typedef struct {
  uint8_t cv[32];
} ConvertDescriptionV5;

typedef struct {
  uint8_t f0[32];
} EphemeralKeyBytes;

typedef struct {
  uint8_t f0[32];
} Nullifier;

typedef struct {
  uint8_t cv[32];
  uint8_t cmu[32];
  EphemeralKeyBytes ephemeral_key;
  uint8_t enc_ciphertext[612];
  uint8_t out_ciphertext[80];
} OutputDescriptionV5;

typedef struct {
  uint8_t f0[32];
} PublicKey;

typedef struct {
  uint8_t rbar[32];
  uint8_t sbar[32];
} Signature;

typedef struct {
  Signature binding_sig;
} Authorized;

typedef struct {
  uint8_t cv[32];
  Nullifier nullifier;
  PublicKey rk;
} SpendDescriptionV5;

typedef struct {
  uint8_t tag;
  union {
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  };
} CompactSize;

typedef struct {
  union {
  Authorized Some;
  };
} Transaction_authorization;

typedef struct {
  union {
  uint8_t Some[32];
  };
} Transaction_convert_anchor;

typedef struct {
  union {
  uint8_t Some[32];
  };
} Transaction_spend_anchor;

typedef struct {
  uint8_t f0[20];
} TransparentAddress;

typedef struct {
  AssetType asset_type;
  uint64_t value;
  TransparentAddress address;
} TxInAuthorized;

typedef struct {
  AssetType asset_type;
  uint64_t value;
  TransparentAddress address;
} TxOut;

typedef struct {
  uint32_t header;
  uint32_t version_group_id;
} TxVersion;

typedef struct {
  CompactSize f0;
  AssetType_i128 *f1;
} ValueSumAssetType_i128;

typedef struct {
  union {
  ValueSumAssetType_i128 Some;
  };
} Transaction_value_balance;

typedef struct {
  TxVersion version;
  BranchId consensus_branch_id;
  uint32_t lock_time;
  BlockHeight expiry_height;
  CompactSize vin_count;
  TxInAuthorized *vin;
  CompactSize vout_count;
  TxOut *vout;
  CompactSize sd_v5s_count;
  SpendDescriptionV5 *sd_v5s;
  CompactSize cd_v5s_count;
  ConvertDescriptionV5 *cd_v5s;
  CompactSize od_v5s_count;
  OutputDescriptionV5 *od_v5s;
  Transaction_value_balance value_balance;
  Transaction_spend_anchor spend_anchor;
  Transaction_convert_anchor convert_anchor;
  uint8_t (*v_spend_proofs)[192];
  Signature *v_spend_auth_sigs;
  uint8_t (*v_convert_proofs)[192];
  uint8_t (*v_output_proofs)[192];
  Transaction_authorization authorization;
} Transaction;

typedef struct {
    bytes_t tx_id; // [u8;32]
  Transaction data;
} masp_tx_section_t;

typedef struct {
  uint8_t f0[20];
} IbcTokenHash;

typedef struct {
  uint8_t f0[20];
} EthAddress;

typedef struct {
  uint8_t f0[20];
} PublicKeyHash;

typedef struct {
  uint8_t f0;
  uint8_t f1[32];
} u8_u8_32;

typedef struct {
  ValueSumAssetType_i128 assets;
  uint8_t generator[32];
} AllowedConversion;

typedef struct {
  uint8_t f0[32];
} ChainCode;

typedef struct {
  uint32_t f0;
} ChildIndex;

typedef struct {
  uint8_t auth_pathLen;
  u8_u8_32 *auth_path;
  uint64_t position;
} MerklePathu8_32;

typedef struct {
  AllowedConversion allowed;
  uint64_t value;
  MerklePathu8_32 merkle_path;
} ConvertDescriptionInfo;

typedef struct {
  uint8_t f0[11];
} Diversifier;

typedef struct {
  uint8_t f0[32];
} DiversifierKey;

typedef struct {
  uint8_t f0[32];
} NullifierDerivingKey;

typedef struct {
  uint8_t ak[32];
  NullifierDerivingKey nk;
} ViewingKey;

typedef struct {
  uint8_t f0[32];
} OutgoingViewingKey;

typedef struct {
  ViewingKey vk;
  OutgoingViewingKey ovk;
} FullViewingKey;

typedef struct {
  uint8_t f0[4];
} FvkTag;

typedef struct {
  uint8_t depth;
  FvkTag parent_fvk_tag;
  ChildIndex child_index;
  ChainCode chain_code;
  FullViewingKey fvk;
  DiversifierKey dk;
} ExtendedFullViewingKey;

typedef struct {
  uint8_t f0[512];
} MemoBytes;

typedef struct {
  uint8_t tag;
  union {
  uint8_t BeforeZip212[32];
  uint8_t AfterZip212[32];
  };
} Rseed;

typedef struct {
  AssetType asset_type;
  uint64_t value;
  uint8_t g_d[32];
  uint8_t pk_d[32];
  Rseed rseed;
} Note;

typedef struct {
  uint8_t tag;
  union {
  OutgoingViewingKey Some;
  };
} OptionOutgoingViewingKey;

typedef struct {
  uint8_t tag;
  union {
  uint8_t Some[32];
  };
} Optionu8_32;

typedef struct {
  Diversifier diversifier;
  uint8_t pk_d[32];
} PaymentAddress;

typedef struct {
  ExtendedFullViewingKey extsk;
  Diversifier diversifier;
  Note note;
  uint8_t alpha[32];
  MerklePathu8_32 merkle_path;
} SpendDescriptionInfoExtendedFullViewingKey;

typedef struct {
  OptionOutgoingViewingKey ovk;
  PaymentAddress to;
  Note note;
  MemoBytes memo;
} SaplingOutputInfo;

typedef struct {
  Optionu8_32 spend_anchor;
  BlockHeight target_height;
  ValueSumAssetType_i128 value_balance;
  Optionu8_32 convert_anchor;
  uint32_t spendsLen;
  SpendDescriptionInfoExtendedFullViewingKey *spends;
  uint32_t convertsLen;
  ConvertDescriptionInfo *converts;
  uint32_t outputsLen;
  SaplingOutputInfo *outputs;
} SaplingBuilder_ExtendedFullViewingKey;

typedef struct {
  TxOut coin;
} TransparentInputInfo;

typedef struct {
  uint32_t inputsLen;
  TransparentInputInfo *inputs;
  uint32_t voutLen;
  TxOut *vout;
} TransparentBuilder;

typedef struct {
  uint8_t tag;
  union {
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  };
} ValueSumAssetType_i128_CompactSize;

typedef struct {
  BlockHeight target_height;
  BlockHeight expiry_height;
  TransparentBuilder transparent_builder;
  SaplingBuilder_ExtendedFullViewingKey sapling_builder;
} Builder__ExtendedFullViewingKey;

typedef struct {
  uint8_t f0[32];
} Hash;

typedef struct {
  uint32_t spend_indicesLen;
  uint64_t *spend_indices;
  uint32_t convert_indicesLen;
  uint64_t *convert_indices;
  uint32_t output_indicesLen;
  uint64_t *output_indices;
} SaplingMetadata;

typedef struct {
  uint8_t hash[20];
} EstablishedAddress;

typedef struct {
  EstablishedAddress f0;
} AddressEstablished;

typedef struct {
  PublicKeyHash f0;
} ImplicitAddress;

typedef struct {
  ImplicitAddress f0;
} AddressImplicit;

typedef struct {
  EthAddress f0;
} InternalAddressErc20;

typedef struct {} InternalAddressEthBridge;

typedef struct {} InternalAddressEthBridgePool;

typedef struct {} InternalAddressGovernance;

typedef struct {} InternalAddressIbc;

typedef struct {
  IbcTokenHash f0;
} InternalAddressIbcToken;

typedef struct {} InternalAddressMasp;

typedef struct {} InternalAddressMultitoken;

typedef struct {
  EthAddress f0;
} InternalAddressNut;

typedef struct {} InternalAddressParameters;

typedef struct {} InternalAddressPgf;

typedef struct {} InternalAddressPoS;

typedef struct {} InternalAddressPosSlashPool;

typedef struct {
  uint8_t tag;
  union {
  InternalAddressPoS PoS;
  InternalAddressPosSlashPool PosSlashPool;
  InternalAddressParameters Parameters;
  InternalAddressIbc Ibc;
  InternalAddressIbcToken IbcToken;
  InternalAddressGovernance Governance;
  InternalAddressEthBridge EthBridge;
  InternalAddressEthBridgePool EthBridgePool;
  InternalAddressErc20 Erc20;
  InternalAddressNut Nut;
  InternalAddressMultitoken Multitoken;
  InternalAddressPgf Pgf;
  InternalAddressMasp Masp;
  };
} InternalAddress;

typedef struct {
  InternalAddress f0;
} AddressInternal;

typedef struct {
  uint8_t tag;
  union {
  AddressEstablished Established;
  AddressImplicit Implicit;
  AddressInternal Internal;
  };
} AddressAlt;

typedef struct {
  uint64_t f0;
} Epoch;

typedef struct {
  uint8_t tag;
  union {
  Epoch Some;
  };
} OptionEpoch;

typedef struct {
  uint8_t f0;
} Denomination;

typedef struct {
  uint8_t tag;
} MaspDigitPos;

typedef struct {
  AddressAlt token;
  Denomination denom;
  MaspDigitPos position;
  OptionEpoch epoch;
} AssetData;

typedef struct {
  Hash target;
  uint32_t asset_typesLen;
  AssetData *asset_types;
  SaplingMetadata metadata;
  Builder__ExtendedFullViewingKey builder;
} MaspBuilder;

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
    uint64_t epoch;
    uint64_t gasLimit;
    bytes_t unshieldSectionHash;
    bytes_t dataHash;
    bytes_t codeHash;
    bytes_t memoHash;
    const section_t *memoSection;
} header_t;
typedef struct {
    uint32_t sectionLen;
    uint32_t extraDataLen;
    uint32_t signaturesLen;
    section_t code;
    section_t data;
    section_t extraData[MAX_EXTRA_DATA_SECS];
    signature_section_t signatures[MAX_SIGNATURE_SECS];
    masp_tx_section_t maspTx;
    MaspBuilder maspBuilder;
#if(0)
    section_t ciphertext; // todo: if we need to parse this in future, it will not be a section_t
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
