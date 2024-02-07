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
#include "parser_impl_common.h"
#include "parser_txdef.h"
#include "crypto_helper.h"
#include "leb128.h"
#include "bech32.h"
#include "stdbool.h"
#include <zxformat.h>

#define DISCRIMINANT_DATA 0x00
#define DISCRIMINANT_EXTRA_DATA 0x01
#define DISCRIMINANT_CODE 0x02
#define DISCRIMINANT_SIGNATURE 0x03
#define DISCRIMINANT_CIPHERTEXT 0x04
#define DISCRIMINANT_MASP_TX 0x05
#define DISCRIMINANT_MASP_BUILDER 0x06

static const txn_types_t allowed_txn[] = {
    {"tx_bond.wasm", Bond},
    {"tx_unbond.wasm", Unbond},
    {"tx_init_account.wasm", InitAccount},
    {"tx_init_proposal.wasm", InitProposal},
    {"tx_vote_proposal.wasm", VoteProposal},
    {"tx_become_validator.wasm", BecomeValidator},
    {"tx_reveal_pk.wasm", RevealPubkey},
    {"tx_transfer.wasm", Transfer},
    {"tx_update_account.wasm", UpdateVP},
    {"tx_withdraw.wasm", Withdraw},
    {"tx_change_validator_commission.wasm", CommissionChange},
    {"tx_unjail_validator.wasm", UnjailValidator},
    {"tx_redelegate.wasm", Redelegate},
    {"tx_reactivate_validator.wasm", ReactivateValidator},
    {"tx_ibc.wasm", IBC},
    {"tx_change_validator_metadata.wasm", ChangeValidatorMetadata},
    {"tx_claim_rewards.wasm", ClaimRewards},
    {"tx_deactivate_validator.wasm", DeactivateValidator},
    {"tx_change_consensus_key.wasm", ChangeConsensusKey},
    {"tx_resign_steward.wasm", ResignSteward},
    {"tx_update_steward_commission.wasm", UpdateStewardCommission},
};
static const uint32_t allowed_txn_len = sizeof(allowed_txn) / sizeof(allowed_txn[0]);

// Update VP types
static const vp_types_t vp_user = { "vp_user.wasm", "User"};
static const vp_types_t vp_validator = { "vp_validator.wasm", "Validator"};

#define NAM_TOKEN(_address, _symbol) { \
        .address  = _address, \
        .symbol = _symbol, \
    }

static const tokens_t nam_tokens[] = {
    NAM_TOKEN("tnam1qye0m4890at9r92pfyf3948fpzgryfzweg2v95fs", "NAM "),
    NAM_TOKEN("tnam1qx3jyxy292rlqu40syq3nfnlgtsusyewkcuyddhp", "BTC "),
    NAM_TOKEN("tnam1q8dug9yu52tzz3mmn976574fj7yfl4yj0qynxvrk", "ETH "),
    NAM_TOKEN("tnam1q8d2xskmexg9j9yvfda7cwy48vy8wrmwsuw5lxtv", "DOT "),
    NAM_TOKEN("tnam1q8qy9puaq5plu2csa4gk3l2fpl5vc4r2ccxqjhqk", "Schnitzel "),
    NAM_TOKEN("tnam1q9zsxkpuk4sle4lhfcfnu5fdep8fy3n2aqufyc97", "Apfel "),
    NAM_TOKEN("tnam1qyev25082t47tqxmj4gd4c07d3pm9t6rnc7jgwyq", "Kartoffel "),
};

#define PREFIX_IMPLICIT 0
#define PREFIX_ESTABLISHED 1
#define PREFIX_INTERNAL 2

parser_error_t readToken(const bytes_t *token, const char **symbol) {
    if (token == NULL || symbol == NULL) {
        return parser_unexpected_value;
    }

    // Convert token to address
    char address[53] = {0};
    CHECK_ERROR(readAddress(*token, address, sizeof(address)))

    *symbol = NULL;

    const uint16_t tokenListLen = sizeof(nam_tokens) / sizeof(nam_tokens[0]);
    for (uint16_t i = 0; i < tokenListLen; i++) {
        if (!memcmp(&address, &nam_tokens[i].address, ADDRESS_LEN_TESTNET)) {
            *symbol = (char*) PIC(nam_tokens[i].symbol);
            return parser_ok;
        }
    }

    return parser_ok;
}

parser_error_t readVPType(const bytes_t *vp_type_tag, const char **vp_type_text) {
    if (vp_type_tag == NULL || vp_type_text == NULL) {
        return parser_unexpected_value;
    }

    *vp_type_text = NULL;
    if (vp_type_tag->ptr == NULL) {
        return parser_ok;
    }

    if (strnlen(vp_user.tag, sizeof(vp_user.tag)) == vp_type_tag->len &&
        !memcmp(vp_type_tag->ptr, vp_user.tag, vp_type_tag->len)) {
        *vp_type_text = (char*) PIC(vp_user.text);
    } else if (strnlen(vp_validator.tag, sizeof(vp_validator.tag)) == vp_type_tag->len &&
               memcmp(vp_type_tag->ptr, vp_validator.tag, vp_type_tag->len) == 0) {
        *vp_type_text = (char*) PIC(vp_validator.text);
    }

    return parser_ok;
}

parser_error_t readAddress(bytes_t pubkeyHash, char *address, uint16_t addressLen) {
    const uint8_t addressType = *pubkeyHash.ptr++;
    uint8_t tmpBuffer[ADDRESS_LEN_BYTES] = {0};

    switch (addressType) {
        case 0:
            tmpBuffer[0] = PREFIX_ESTABLISHED;
            break;
        case 1:
            tmpBuffer[1] = PREFIX_IMPLICIT;
            break;
        case 2:
            tmpBuffer[2] = PREFIX_INTERNAL;
            break;

        default:
            return parser_value_out_of_range;
    }

    MEMCPY(tmpBuffer + 1, pubkeyHash.ptr, 20);

    // Check HRP for mainnet/testnet
    const char *hrp = "tnam";
    const zxerr_t err = bech32EncodeFromBytes(address,
                                addressLen,
                                hrp,
                                (uint8_t*) tmpBuffer,
                                ADDRESS_LEN_BYTES,
                                1,
                                BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

static parser_error_t readTransactionType(bytes_t *codeTag, transaction_type_e *type) {
    if (codeTag == NULL || type == NULL) {
         return parser_unexpected_error;
    }

    // Custom txn as default value
    *type = Custom;
    if (codeTag->ptr == NULL) {
        return parser_ok;
    }

    for (uint32_t i = 0; i < allowed_txn_len; i++) {
        if (strnlen(allowed_txn[i].tag, sizeof(allowed_txn[i].tag)) == codeTag->len &&
            memcmp(codeTag->ptr, allowed_txn[i].tag, codeTag->len) == 0) {
            *type = allowed_txn[i].type;
            break;
        }
    }
    return parser_ok;
}

static parser_error_t readPublicKey(parser_context_t *ctx, bytes_t *pubKey, bool init) {
    if (init) {
        pubKey->ptr = ctx->buffer + ctx->offset;
        pubKey->len = 0;
    }
    // Read the public key's tag
    uint8_t tag = 0;
    CHECK_ERROR(readByte(ctx, &tag))
    pubKey->len += 1;
    if (tag != key_ed25519 && tag != key_secp256k1) {
        return parser_unexpected_value;
    }
    // Read the public key proper
    const uint8_t keySize = tag == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN;
    uint8_t *tmpOutput = NULL;
    CHECK_ERROR(readBytes(ctx, (const uint8_t **) &tmpOutput, keySize));
    pubKey->len += keySize;
    
    return parser_ok;
}

static parser_error_t readBecomeValidatorTxn(bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    v->becomeValidator.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.address.ptr, v->becomeValidator.address.len))
    CHECK_ERROR(readPublicKey(&ctx, &v->becomeValidator.consensus_key, true))
    v->becomeValidator.eth_cold_key.len = COMPRESSED_SECP256K1_PK_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.eth_cold_key.ptr, v->becomeValidator.eth_cold_key.len))
    v->becomeValidator.eth_hot_key.len = COMPRESSED_SECP256K1_PK_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.eth_hot_key.ptr, v->becomeValidator.eth_hot_key.len))
    CHECK_ERROR(readPublicKey(&ctx, &v->becomeValidator.protocol_key, true))
    // Commission rate
    CHECK_ERROR(readInt256(&ctx, &v->becomeValidator.commission_rate));

    // Max commission rate change
    CHECK_ERROR(readInt256(&ctx, &v->becomeValidator.max_commission_rate_change));

    uint32_t tmpValue = 0;
    // The validator email
    CHECK_ERROR(readUint32(&ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    v->becomeValidator.email.len = (uint16_t)tmpValue;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.email.ptr, v->becomeValidator.email.len))

    /// The validator description
    v->becomeValidator.description.ptr = NULL;
    v->becomeValidator.description.len = 0;
    uint8_t has_description = 0;
    CHECK_ERROR(readByte(&ctx, &has_description))
    if (has_description != 0 && has_description != 1) {
        return parser_value_out_of_range;
    }

    if (has_description) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.description.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.description.ptr, v->becomeValidator.description.len))
    }

    /// The validator website
    v->becomeValidator.website.ptr = NULL;
    v->becomeValidator.website.len = 0;
    uint8_t has_website;
    CHECK_ERROR(readByte(&ctx, &has_website))
    if (has_website) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.website.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.website.ptr, v->becomeValidator.website.len))
    }

    /// The validator's discord handle
    v->becomeValidator.discord_handle.ptr = NULL;
    v->becomeValidator.discord_handle.len = 0;
    uint8_t has_discord_handle;
    CHECK_ERROR(readByte(&ctx, &has_discord_handle))
    if (has_discord_handle) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.discord_handle.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.discord_handle.ptr, v->becomeValidator.discord_handle.len))
    }

    /// The validator's discord handle
    v->becomeValidator.avatar.ptr = NULL;
    v->becomeValidator.avatar.len = 0;
    uint8_t has_avatar;
    CHECK_ERROR(readByte(&ctx, &has_avatar))
    if (has_avatar) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.avatar.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.avatar.ptr, v->becomeValidator.avatar.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readInitAccountTxn(const bytes_t *data,const section_t *extra_data,const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    // Pubkey
    v->initAccount.number_of_pubkeys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->initAccount.number_of_pubkeys))
    v->initAccount.pubkeys.len = 0;
    for (uint32_t i = 0; i < v->initAccount.number_of_pubkeys; i++) {
      CHECK_ERROR(readPublicKey(&ctx, &v->initAccount.pubkeys, !i))
    }

    // VP code hash
    v->initAccount.vp_type_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.vp_type_sechash.ptr, v->initAccount.vp_type_sechash.len))

    // Threshold
    CHECK_ERROR(readByte(&ctx, &v->initAccount.threshold))

    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initAccount.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->initAccount.vp_type_secidx = extra_data[i].idx;
            MEMCPY(v->initAccount.vp_type_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            CHECK_ERROR(readVPType(&extra_data[i].tag, &v->initAccount.vp_type_text))
            found_vp_code = true;
        }
    }

    if (!found_vp_code) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readPGFPaymentAction(parser_context_t *ctx, bytes_t *buf, const bool first) {
    const uint8_t tag = *(ctx->buffer + ctx->offset);
    uint32_t action_len = 1 + ADDRESS_LEN_BYTES + 32;
    switch (tag) {
        case 0: // continuous payment
            action_len += 1;
            break;
        case 1: // retro payment
            // do nothing
            break;
        default:
            return parser_unexpected_value;
    }

    if (first) {
        buf->len = action_len;
        CHECK_ERROR(readBytes(ctx, &buf->ptr, buf->len))
    } else {
        buf->len += action_len;
        uint8_t *tmpPtr = NULL;
        CHECK_ERROR(readBytes(ctx, (const uint8_t **) &tmpPtr, action_len))
    }

    return parser_ok;
}

static parser_error_t readInitProposalTxn(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    MEMZERO(&v->initProposal, sizeof(v->initProposal));

    // Check if the proposal has an ID
    CHECK_ERROR(readByte(&ctx, &v->initProposal.has_id))
    if (v->initProposal.has_id){
        CHECK_ERROR(readUint64(&ctx, &v->initProposal.proposal_id));
    }

    // Read content section hash
    v->initProposal.content_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.content_sechash.ptr, v->initProposal.content_sechash.len))

    // Author, should be of length ADDRESS_LEN_BYTES
    v->initProposal.author.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.author.ptr, v->initProposal.author.len))

    // Proposal type
    v->initProposal.has_proposal_code = 0;
    CHECK_ERROR(readByte(&ctx, &v->initProposal.proposal_type))
    switch (v->initProposal.proposal_type) {
        case Default: {
            // Proposal type 0 is Default(Option<Hash>), where Hash is the proposal code.
            CHECK_ERROR(readByte(&ctx, &v->initProposal.has_proposal_code))
            if (v->initProposal.has_proposal_code) {
                v->initProposal.proposal_code_sechash.len = HASH_LEN;
                CHECK_ERROR(readBytes(&ctx, &v->initProposal.proposal_code_sechash.ptr, v->initProposal.proposal_code_sechash.len))
            }
            break;
        }

        case PGFSteward: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_steward_actions_num))
            if (v->initProposal.pgf_steward_actions_num > 0) {
                v->initProposal.pgf_steward_actions.len = (1 + ADDRESS_LEN_BYTES) * v->initProposal.pgf_steward_actions_num;
                CHECK_ERROR(readBytes(&ctx, &v->initProposal.pgf_steward_actions.ptr, v->initProposal.pgf_steward_actions.len))
            }
            break;
        }

        case PGFPayment: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_payment_actions_num))
            if (v->initProposal.pgf_payment_actions_num > 0) {
                CHECK_ERROR(readPGFPaymentAction(&ctx, &v->initProposal.pgf_payment_actions, true))
                for (uint32_t i = 1; i < v->initProposal.pgf_payment_actions_num; ++i) {
                    CHECK_ERROR(readPGFPaymentAction(&ctx, &v->initProposal.pgf_payment_actions, false))
                }
            }
            break;
        }

        default:
            return parser_unexpected_type;
    }

    // Voting start epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_start_epoch))

    // Voting end epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_end_epoch))

    // Grace epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.grace_epoch))

    bool found_content = false, found_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initProposal.content_sechash.ptr, HASH_LEN)) {
            // If this section contains the init proposal content
            v->initProposal.content_secidx = extra_data[i].idx;
            MEMCPY(v->initProposal.content_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            found_content = true;
        }
        if (v->initProposal.has_proposal_code &&
            !memcmp(extraDataHash, v->initProposal.proposal_code_sechash.ptr, HASH_LEN))
        {
            // If this section contains the proposal code
            v->initProposal.proposal_code_secidx = extra_data[i].idx;
            MEMCPY(v->initProposal.proposal_code_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            found_code = true;
        }
    }

    const bool code_condition = (v->initProposal.proposal_type == Default) && (v->initProposal.has_proposal_code && !found_code);
    if (!found_content || code_condition) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readVoteProposalTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Proposal ID
    CHECK_ERROR(readUint64(&ctx, &v->voteProposal.proposal_id))
    // Proposal vote
    CHECK_ERROR(readByte(&ctx, (uint8_t*) &v->voteProposal.proposal_vote))

    // Voter, should be of length ADDRESS_LEN_BYTES
    v->voteProposal.voter.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->voteProposal.voter.ptr, v->voteProposal.voter.len))

    // Delegators
    v->voteProposal.number_of_delegations = 0;
    CHECK_ERROR(readUint32(&ctx, &v->voteProposal.number_of_delegations))
    v->voteProposal.delegations.len = 0;
    if (v->voteProposal.number_of_delegations > 0 ){
        v->voteProposal.delegations.len = ADDRESS_LEN_BYTES*v->voteProposal.number_of_delegations;
        CHECK_ERROR(readBytes(&ctx, &v->voteProposal.delegations.ptr, v->voteProposal.delegations.len))
          }

    if ((ctx.offset != ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readRevealPubkeyTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    // Pubkey
    CHECK_ERROR(readPublicKey(&ctx, &v->revealPubkey.pubkey, true))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

parser_error_t readAddressBytes(parser_context_t *ctx, bytes_t *address) {
  address->len = ADDRESS_LEN_BYTES;
  CHECK_ERROR(readBytes(ctx, &address->ptr, address->len))
  return parser_ok;
}

static parser_error_t readUpdateStewardCommissionTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    
    // Address
    v->updateStewardCommission.steward.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->updateStewardCommission.steward.ptr, v->updateStewardCommission.steward.len))

    v->updateStewardCommission.commissionLen = 0;
    CHECK_ERROR(readUint32(&ctx, &v->updateStewardCommission.commissionLen))
      
      v->updateStewardCommission.commission.ptr = ctx.buffer + ctx.offset;
      for (uint32_t i = 0; i < v->updateStewardCommission.commissionLen; i++) {
        bytes_t address;
        CHECK_ERROR(readAddressBytes(&ctx, &address))
          int256_t dec;
        CHECK_ERROR(readInt256(&ctx, &dec))
      }
      v->updateStewardCommission.commission.len = ctx.buffer + ctx.offset - v->updateStewardCommission.commission.ptr;
      
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readReactivateValidatorTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->reactivateValidator.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->reactivateValidator.validator.ptr, v->reactivateValidator.validator.len))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readResignStewardTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->resignSteward.steward.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->resignSteward.steward.ptr, v->resignSteward.steward.len))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readDeactivateValidatorTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->deactivateValidator.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->deactivateValidator.validator.ptr, v->deactivateValidator.validator.len))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readChangeConsensusKeyTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->consensusKeyChange.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->consensusKeyChange.validator.ptr, v->consensusKeyChange.validator.len))
    // Consensus key
    CHECK_ERROR(readPublicKey(&ctx, &v->consensusKeyChange.consensus_key, true))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readUnjailValidatorTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Address
    if (ctx.bufferLen != ADDRESS_LEN_BYTES) {
        return parser_unexpected_value;
    }
    v->revealPubkey.pubkey.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->unjailValidator.validator.ptr, v->unjailValidator.validator.len))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readWithdrawTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->withdraw.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->withdraw.validator.ptr, v->withdraw.validator.len))

    // Does this tx specify the source
    CHECK_ERROR(readByte(&ctx, &v->withdraw.has_source))

    // Source
    if (v->withdraw.has_source != 0) {
        v->withdraw.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->withdraw.source.ptr, v->withdraw.source.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readClaimRewardsTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->withdraw.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->withdraw.validator.ptr, v->withdraw.validator.len))

    // Does this tx specify the source
    CHECK_ERROR(readByte(&ctx, &v->withdraw.has_source))

    // Source
    if (v->withdraw.has_source != 0) {
        v->withdraw.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->withdraw.source.ptr, v->withdraw.source.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readChangeValidatorMetadataTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->metadataChange.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->metadataChange.validator.ptr, v->metadataChange.validator.len))

    uint32_t tmpValue = 0;
    // The validator email
    v->metadataChange.email.ptr = NULL;
    v->metadataChange.email.len = 0;
    uint8_t has_email = 0;
    CHECK_ERROR(readByte(&ctx, &has_email))
    if (has_email != 0 && has_email != 1) {
        return parser_value_out_of_range;
    }
    if (has_email) {
      CHECK_ERROR(readUint32(&ctx, &tmpValue));
      if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
      }
      v->metadataChange.email.len = (uint16_t)tmpValue;
      CHECK_ERROR(readBytes(&ctx, &v->metadataChange.email.ptr, v->metadataChange.email.len))
    }

    /// The validator description
    v->metadataChange.description.ptr = NULL;
    v->metadataChange.description.len = 0;
    uint8_t has_description = 0;
    CHECK_ERROR(readByte(&ctx, &has_description))
    if (has_description != 0 && has_description != 1) {
        return parser_value_out_of_range;
    }
    if (has_description) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->metadataChange.description.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->metadataChange.description.ptr, v->metadataChange.description.len))
    }

    /// The validator website
    v->metadataChange.website.ptr = NULL;
    v->metadataChange.website.len = 0;
    uint8_t has_website;
    CHECK_ERROR(readByte(&ctx, &has_website))
    if (has_website) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->metadataChange.website.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->metadataChange.website.ptr, v->metadataChange.website.len))
    }

    /// The validator's discord handle
    v->metadataChange.discord_handle.ptr = NULL;
    v->metadataChange.discord_handle.len = 0;
    uint8_t has_discord_handle;
    CHECK_ERROR(readByte(&ctx, &has_discord_handle))
    if (has_discord_handle) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->metadataChange.discord_handle.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->metadataChange.discord_handle.ptr, v->metadataChange.discord_handle.len))
    }

    /// The validator's avatar
    v->metadataChange.avatar.ptr = NULL;
    v->metadataChange.avatar.len = 0;
    uint8_t has_avatar;
    CHECK_ERROR(readByte(&ctx, &has_avatar))
    if (has_avatar) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->metadataChange.avatar.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->metadataChange.avatar.ptr, v->metadataChange.avatar.len))
    }

    // Commission rate
    CHECK_ERROR(readByte(&ctx, &v->metadataChange.has_commission_rate))
    if (v->metadataChange.has_commission_rate) {
        CHECK_ERROR(readInt256(&ctx, &v->metadataChange.commission_rate));
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readCommissionChangeTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->commissionChange.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->commissionChange.validator.ptr, v->commissionChange.validator.len))

    // Read new commission rate
    CHECK_ERROR(readInt256(&ctx, &v->commissionChange.new_rate));


    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}


static parser_error_t readUpdateVPTxn(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    
    // Address
    v->updateVp.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->updateVp.address.ptr, v->updateVp.address.len))

    // VP code hash (optional)
    CHECK_ERROR(readByte(&ctx, &v->updateVp.has_vp_code));
    if (v->updateVp.has_vp_code) {
        v->updateVp.vp_type_sechash.len = HASH_LEN;
        CHECK_ERROR(readBytes(&ctx, &v->updateVp.vp_type_sechash.ptr, v->updateVp.vp_type_sechash.len))
    }
    

    // Pubkeys
    v->updateVp.number_of_pubkeys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->updateVp.number_of_pubkeys))
    v->updateVp.pubkeys.len = 0;
    
    for (uint32_t i = 0; i < v->updateVp.number_of_pubkeys; i++) {
        readPublicKey(&ctx, &v->updateVp.pubkeys, !i);
    }

    // Threshold (optional)
    CHECK_ERROR(readByte(&ctx, &v->updateVp.has_threshold))
    if (v->updateVp.has_threshold != 0) {
        CHECK_ERROR(readByte(&ctx, &v->updateVp.threshold))
    }

    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen * v->updateVp.has_vp_code; i++) {
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->updateVp.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->updateVp.vp_type_secidx = extra_data[i].idx;
            MEMCPY(v->updateVp.vp_type_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            CHECK_ERROR(readVPType(&extra_data[i].tag, &v->updateVp.vp_type_text))
            found_vp_code = true;
        }
    }

    if (v->updateVp.has_vp_code && !found_vp_code) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readTransferTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    
    // Source
    v->transfer.source_address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.source_address.ptr, v->transfer.source_address.len))

    // Target
    v->transfer.target_address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.target_address.ptr, v->transfer.target_address.len))

    // Token
    v->transfer.token.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.token.ptr, v->transfer.token.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transfer.token, &v->transfer.symbol))

    // Amount
    CHECK_ERROR(readUint256(&ctx, &v->transfer.amount))

    // Amount denomination
    CHECK_ERROR(readByte(&ctx, &v->transfer.amount_denom))

    uint32_t tmpValue = 0;
    // Key, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_key))
    if (v->transfer.has_key){
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->transfer.key.len = (uint16_t)tmpValue;
        // we are not displaying these bytes
        ctx.offset += v->transfer.key.len;
    }
    // shielded hash, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_shielded_hash))
    if (v->transfer.has_shielded_hash){
        v->transfer.shielded_hash.len = HASH_LEN;
        // we are not displaying these bytes
        ctx.offset += v->transfer.shielded_hash.len;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readRedelegateTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    
    // Source validator
    v->redelegation.src_validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->redelegation.src_validator.ptr, v->redelegation.src_validator.len))

    // Destination validator
    v->redelegation.dest_validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->redelegation.dest_validator.ptr, v->redelegation.dest_validator.len))

    // Owner
    v->redelegation.owner.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->redelegation.owner.ptr, v->redelegation.owner.len))

    // Amount
    CHECK_ERROR(readUint256(&ctx, &v->redelegation.amount))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readBondUnbondTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/transaction/pos.rs#L24-L35
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->bond.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->bond.validator.ptr, v->bond.validator.len))

    // Amount
    MEMCPY(&v->bond.amount, ctx.buffer + ctx.offset, sizeof(uint256_t));
    ctx.offset += sizeof(uint256_t);
    readByte(&ctx, &v->bond.has_source);

    // Source
    if (v->bond.has_source) {
        v->bond.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->bond.source.ptr, v->bond.source.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readTimestamp(parser_context_t *ctx, timestamp_t *timestamp) {
    uint8_t consumed = 0;
    uint64_t tmp = 0;

    CHECK_ERROR(checkTag(ctx, 0x38))
    const uint64_t timestampSize = ctx->bufferLen - ctx->offset;
    decodeLEB128(ctx->buffer + ctx->offset, timestampSize, &consumed, &tmp);
    ctx->offset += consumed;

    const uint32_t e9 = 1000000000;
    timestamp->millis = tmp / e9;
    timestamp->nanos = (uint32_t)(tmp - timestamp->millis*e9);

    return parser_ok;
}

static parser_error_t readIBCTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Read tag
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    // Skip URL: /ibc.applications.transfer.v1.MsgTransfer
    uint8_t tmp = 0;
    CHECK_ERROR(readByte(&ctx, &tmp))
    ctx.offset += tmp;

    CHECK_ERROR(checkTag(&ctx, 0x12))
    // Missing bytes
    CHECK_ERROR(readByte(&ctx, &tmp))
    CHECK_ERROR(readByte(&ctx, &tmp))

    // Read port id
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.port_id.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.port_id.ptr, v->ibc.port_id.len))

    // Read channel id
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.channel_id.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.channel_id.ptr, v->ibc.channel_id.len))

    // Read token address
    CHECK_ERROR(checkTag(&ctx, 0x1A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.token_address.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.token_address.ptr, v->ibc.token_address.len))

    // Read token amount
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.token_amount.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.token_amount.ptr, v->ibc.token_amount.len))

    // Read sender
    CHECK_ERROR(checkTag(&ctx, 0x22))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.sender_address.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.sender_address.ptr, v->ibc.sender_address.len))

    // Read receiver
    CHECK_ERROR(checkTag(&ctx, 0x2A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.receiver.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.receiver.ptr, v->ibc.receiver.len))

    // Read timeout height
    CHECK_ERROR(checkTag(&ctx, 0x32))
    CHECK_ERROR(readByte(&ctx, &v->ibc.timeout_height))

    // Read timeout timestamp
    CHECK_ERROR(readTimestamp(&ctx, &v->ibc.timeout_timestamp))

    return parser_ok;
}

parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    v->transaction.header.bytes.ptr = ctx->buffer + ctx->offset;
    v->transaction.header.extBytes.ptr = ctx->buffer + ctx->offset;
    const uint16_t tmpOffset = ctx->offset;

    // Read length of chain_id
    uint32_t chain_id_len = 0;
    CHECK_ERROR(readUint32(ctx, &chain_id_len))

    ctx->offset += chain_id_len;

    // Check if an expiration is set
    uint8_t has_expiration = 0;
    CHECK_ERROR(readByte(ctx, &has_expiration))
    if (has_expiration){
        // If so, read the length of expiration, and skip it
        uint32_t expiration_len = 0;
        CHECK_ERROR(readUint32(ctx, &expiration_len))
        ctx->offset += expiration_len;
    }

    uint32_t tmpValue = 0;
    // Timestamp
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    v->transaction.timestamp.len = (uint16_t)tmpValue;
    CHECK_ERROR(readBytes(ctx, &v->transaction.timestamp.ptr, v->transaction.timestamp.len))

    // Code hash
    v->transaction.header.codeHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // Data hash
    v->transaction.header.dataHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))

    // Memo hash
    v->transaction.header.memoHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.memoHash.ptr, v->transaction.header.memoHash.len))

    v->transaction.header.bytes.len = ctx->offset - tmpOffset;

    CHECK_ERROR(checkTag(ctx, 0x01))
    // Fee.amount
    CHECK_ERROR(readUint256(ctx, &v->transaction.header.fees.amount))
    CHECK_ERROR(readByte(ctx, &v->transaction.header.fees.amount_denom))

    // Fee.address
    v->transaction.header.fees.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.address.ptr, v->transaction.header.fees.address.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transaction.header.fees.address, &v->transaction.header.fees.symbol))
    // Pubkey
    readPublicKey(ctx, &v->transaction.header.pubkey, true);
    //v->transaction.header.pubkey.len = PK_LEN_25519_PLUS_TAG;   // Check tag (first byte: 0x00 | 0x01)
    //CHECK_ERROR(readBytes(ctx, &v->transaction.header.pubkey.ptr, v->transaction.header.pubkey.len))
    // Epoch
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.epoch))
    // GasLimit
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.gasLimit))
    
    // Unshielded section hash
    uint8_t has_unshield_section_hash = 0;
    CHECK_ERROR(readByte(ctx, &has_unshield_section_hash))
    if (has_unshield_section_hash){
        v->transaction.header.unshieldSectionHash.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &v->transaction.header.unshieldSectionHash.ptr, v->transaction.header.unshieldSectionHash.len))
    }

    v->transaction.header.extBytes.len = ctx->offset - tmpOffset;

    return parser_ok;
}

static parser_error_t readSalt(parser_context_t *ctx, bytes_t *salt) {
    if (ctx == NULL || salt == NULL) {
        return parser_unexpected_error;
    }
    salt->len = SALT_LEN;
    CHECK_ERROR(readBytes(ctx, &salt->ptr, salt->len))

    return parser_ok;
}

static parser_error_t readExtraDataSection(parser_context_t *ctx, section_t *extraData) {
    if (ctx == NULL || extraData == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &extraData->discriminant))
    if (extraData->discriminant != DISCRIMINANT_EXTRA_DATA) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &extraData->salt))
    CHECK_ERROR(readByte(ctx, &extraData->commitmentDiscriminant))
    if (extraData->commitmentDiscriminant) {
      uint32_t bytesLen;
      CHECK_ERROR(readUint32(ctx, &bytesLen));
      extraData->bytes.len = bytesLen;
      CHECK_ERROR(readBytes(ctx, &extraData->bytes.ptr, extraData->bytes.len))
    } else {
      uint8_t const * code_hash;
      CHECK_ERROR(readBytes(ctx, &code_hash, HASH_LEN))
      MEMCPY(extraData->bytes_hash, code_hash, HASH_LEN);
    }

    extraData->tag.ptr = NULL;
    extraData->tag.len = 0;
    uint8_t has_tag = 0;
    CHECK_ERROR(readByte(ctx, &has_tag))
    if (has_tag != 0 && has_tag != 1) {
        return parser_value_out_of_range;
    }

    uint32_t tmpValue = 0;
    if (has_tag) {
        CHECK_ERROR(readUint32(ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        extraData->tag.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(ctx, &extraData->tag.ptr, extraData->tag.len))
    }

    if (crypto_computeCodeHash(extraData) != zxerr_ok) {
        return parser_unexpected_error;
    }

    return parser_ok;
}

static parser_error_t readSignatureSection(parser_context_t *ctx, signature_section_t *signature) {
    if (ctx == NULL || signature == NULL) {
        return parser_unexpected_error;
    }

    uint8_t sectionDiscriminant = 0;
    CHECK_ERROR(readByte(ctx, &sectionDiscriminant))
    if (sectionDiscriminant != DISCRIMINANT_SIGNATURE) {
        return parser_unexpected_value;
    }

    CHECK_ERROR(readUint32(ctx, &signature->hashes.hashesLen))
    signature->hashes.hashes.len = HASH_LEN * signature->hashes.hashesLen;
    CHECK_ERROR(readBytes(ctx, (const uint8_t **) &signature->hashes.hashes.ptr, signature->hashes.hashes.len))

    CHECK_ERROR(readByte(ctx, (uint8_t *) &signature->signerDiscriminant))
    switch (signature->signerDiscriminant) {
        case PubKeys:
        CHECK_ERROR(readUint32(ctx, &signature->pubKeysLen))
        signature->pubKeys.len = 0;
        CHECK_ERROR(readBytes(ctx, &signature->pubKeys.ptr, signature->pubKeys.len))
        for (uint32_t i = 0; i < signature->pubKeysLen; i++) {
            // Read the public key's tag
            uint8_t tag = 0;
            CHECK_ERROR(readByte(ctx, &tag))
            signature->pubKeys.len ++;
            if (tag != key_ed25519 && tag != key_secp256k1) {
                return parser_unexpected_value;
            }
            // Read the public key proper
            const uint8_t signatureSize = tag == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN;
            uint8_t *tmpOutput = NULL;
            CHECK_ERROR(readBytes(ctx, (const uint8_t **) &tmpOutput, signatureSize));
            signature->pubKeys.len += signatureSize;
        }
        break;

        case Address:
        signature->address.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(ctx, &signature->address.ptr, signature->address.len))
        break;

        default:
            return parser_unexpected_value;
    }

    CHECK_ERROR(readUint32(ctx, &signature->signaturesLen))
    signature->indexedSignatures.len = 0;
    CHECK_ERROR(readBytes(ctx, &signature->indexedSignatures.ptr, signature->indexedSignatures.len))

    for (uint32_t i = 0; i < signature->signaturesLen; i++) {
        // Skip the signature's 1 byte index
        ctx->offset ++;
        signature->indexedSignatures.len ++;
        // Read the signature's tag
        uint8_t tag = 0;
        CHECK_ERROR(readByte(ctx, &tag))
        signature->indexedSignatures.len ++;
        if (tag != key_ed25519 && tag != key_secp256k1) {
                return parser_unexpected_value;
        }
        const uint8_t signatureSize = tag == key_ed25519 ? ED25519_SIGNATURE_SIZE : SIG_SECP256K1_LEN;
        uint8_t *tmpOutput = NULL;
        CHECK_ERROR(readBytes(ctx, (const uint8_t **) &tmpOutput, signatureSize));
        signature->indexedSignatures.len += signatureSize;
    }

    return parser_ok;
}

static parser_error_t readDataSection(parser_context_t *ctx, section_t *data) {
    if (ctx == NULL || data == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &data->discriminant))
    if (data->discriminant != DISCRIMINANT_DATA) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &data->salt))
    uint32_t tmpValue = 0;
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    data->bytes.len = (uint16_t)tmpValue;
    CHECK_ERROR(readBytes(ctx, &data->bytes.ptr, data->bytes.len))

    // Must make sure that header dataHash refers to this section's hash
    uint8_t dataHash[HASH_LEN] = {0};
    if (crypto_hashDataSection(data, dataHash, sizeof(dataHash)) != zxerr_ok) {
        return parser_unexpected_error;
    }
    header_t *header = &ctx->tx_obj->transaction.header;
    if (memcmp(dataHash, header->dataHash.ptr, header->dataHash.len) != 0) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

static parser_error_t readCodeSection(parser_context_t *ctx, section_t *code) {
    if (ctx == NULL || code == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &code->discriminant))
    if (code->discriminant != DISCRIMINANT_CODE) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &code->salt))
    CHECK_ERROR(readByte(ctx, &code->commitmentDiscriminant))
    if (code->commitmentDiscriminant) {
      uint32_t bytesLen;
      CHECK_ERROR(readUint32(ctx, &bytesLen));
      code->bytes.len = bytesLen;
      CHECK_ERROR(readBytes(ctx, &code->bytes.ptr, code->bytes.len))
    } else {
      uint8_t const *code_hash;
      CHECK_ERROR(readBytes(ctx, &code_hash, HASH_LEN))
      MEMCPY(code->bytes_hash, code_hash, HASH_LEN);
    }

    code->tag.ptr = NULL;
    code->tag.len = 0;
    uint8_t has_tag = 0;
    CHECK_ERROR(readByte(ctx, &has_tag))
    if (has_tag != 0 && has_tag != 1) {
        return parser_value_out_of_range;
    }

    if (has_tag) {
        uint32_t tmpValue = 0;
        CHECK_ERROR(readUint32(ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        code->tag.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(ctx, &code->tag.ptr, code->tag.len))
    }

    // Must make sure that header codeHash refers to this section's hash
    uint8_t codeHash[HASH_LEN] = {0};
    if (crypto_hashCodeSection(code, codeHash, sizeof(codeHash)) != zxerr_ok) {
        return parser_unexpected_error;
    }
    header_t *header = &ctx->tx_obj->transaction.header;
    if (memcmp(codeHash, header->codeHash.ptr, header->codeHash.len) != 0) {
        return parser_unexpected_value;
    }
    if (crypto_computeCodeHash(code) != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

#if(0)
static parser_error_t readCiphertext(parser_context_t *ctx, section_t *ciphertext) {
    (void) ctx;
    (void) ciphertext;
    return parser_ok;
}


static parser_error_t readMaspTx(parser_context_t *ctx, section_t *maspTx) {
    ctx->offset += 1171; // <- Transfer 2 // Transfer 1 -> 2403;//todo figure out correct number, fix this hack
    (void) maspTx;
    return parser_ok;
}

static parser_error_t readMaspBuilder(parser_context_t *ctx, section_t *maspBuilder) {
    ctx->offset += 941; // <- Transfer 2 // Transfer 1 -> 3060; //todo figure out correct number, fix this hack
    (void) maspBuilder;
    return parser_ok;
}
#endif
parser_error_t readSections(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readUint32(ctx, &v->transaction.sections.sectionLen))
    if (v->transaction.sections.sectionLen > 7) {
        return parser_invalid_output_buffer;
    }

    v->transaction.sections.extraDataLen = 0;
    v->transaction.sections.signaturesLen = 0;

    for (uint32_t i = 0; i < v->transaction.sections.sectionLen; i++) {
        if (ctx->offset >= ctx->bufferLen) {
            return parser_unexpected_error;
        }
        const uint8_t discriminant = *(ctx->buffer + ctx->offset);
        switch (discriminant) {
            case DISCRIMINANT_DATA: {
                CHECK_ERROR(readDataSection(ctx, &v->transaction.sections.data))
                v->transaction.sections.data.idx = i+1;
                break;
            }
            case DISCRIMINANT_EXTRA_DATA: {
                if (v->transaction.sections.extraDataLen >= MAX_EXTRA_DATA_SECS) {
                    return parser_unexpected_field;
                }
                section_t *extraData = &v->transaction.sections.extraData[v->transaction.sections.extraDataLen++];
                CHECK_ERROR(readExtraDataSection(ctx, extraData))
                extraData->idx = i+1;
                break;
            }
            case DISCRIMINANT_CODE: {
                CHECK_ERROR(readCodeSection(ctx, &v->transaction.sections.code))
                v->transaction.sections.code.idx = i+1;
                break;
            }
            case DISCRIMINANT_SIGNATURE: {
                if (v->transaction.sections.signaturesLen >= MAX_SIGNATURE_SECS) {
                    return parser_value_out_of_range;
                }
                signature_section_t *signature = &v->transaction.sections.signatures[v->transaction.sections.signaturesLen++];
                CHECK_ERROR(readSignatureSection(ctx, signature))
                signature->idx = i+1;
                break;
            }
#if(0)
            case DISCRIMINANT_CIPHERTEXT:
                CHECK_ERROR(readCiphertext(ctx, &v->transaction.sections.ciphertext))
                break;

            case DISCRIMINANT_MASP_TX:
                CHECK_ERROR(readMaspTx(ctx, &v->transaction.sections.maspTx))
                break;

            case DISCRIMINANT_MASP_BUILDER:
                CHECK_ERROR(readMaspBuilder(ctx, &v->transaction.sections.maspBuilder))
                break;
#endif
            default:
                return parser_unexpected_field;
        }
    }

    return parser_ok;
}

parser_error_t validateTransactionParams(parser_tx_t *txObj) {
    if (txObj == NULL) {
        return parser_unexpected_error;
    }

    txObj->transaction.header.memoSection = NULL;
    if (!isAllZeroes(txObj->transaction.header.memoHash.ptr, txObj->transaction.header.memoHash.len)) {
      section_t *extra_data = txObj->transaction.sections.extraData;
      // Load the linked to data from the extra data sections
      for (uint32_t i = 0; i < txObj->transaction.sections.extraDataLen; i++) {
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
          return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, txObj->transaction.header.memoHash.ptr, HASH_LEN)) {
          // If this section contains the memo
          txObj->transaction.header.memoSection = &extra_data[i];
        }
      }
      if (!txObj->transaction.header.memoSection) {
        return parser_unexpected_error;
      }
    }

    CHECK_ERROR(readTransactionType(&txObj->transaction.sections.code.tag, &txObj->typeTx))
    switch (txObj->typeTx) {
        case Bond:
        case Unbond:
            CHECK_ERROR(readBondUnbondTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case Custom:
            break;
        case Transfer:
            CHECK_ERROR(readTransferTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case InitAccount:
            CHECK_ERROR(readInitAccountTxn(&txObj->transaction.sections.data.bytes,txObj->transaction.sections.extraData,txObj->transaction.sections.extraDataLen,txObj))
            break;
        case InitProposal:
            CHECK_ERROR(readInitProposalTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case VoteProposal:
            CHECK_ERROR(readVoteProposalTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case RevealPubkey:
            CHECK_ERROR(readRevealPubkeyTxn(&txObj->transaction.sections.data.bytes,  txObj))
            break;
        case Withdraw:
            CHECK_ERROR(readWithdrawTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ClaimRewards:
            CHECK_ERROR(readClaimRewardsTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case CommissionChange:
            CHECK_ERROR(readCommissionChangeTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case BecomeValidator:
            CHECK_ERROR(readBecomeValidatorTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UpdateVP:
            CHECK_ERROR(readUpdateVPTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UnjailValidator:
            CHECK_ERROR(readUnjailValidatorTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case Redelegate:
            CHECK_ERROR(readRedelegateTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ReactivateValidator:
            CHECK_ERROR(readReactivateValidatorTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case DeactivateValidator:
            CHECK_ERROR(readDeactivateValidatorTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ChangeValidatorMetadata:
            CHECK_ERROR(readChangeValidatorMetadataTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case IBC:
            CHECK_ERROR(readIBCTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ChangeConsensusKey:
            CHECK_ERROR(readChangeConsensusKeyTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ResignSteward:
            CHECK_ERROR(readResignStewardTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case UpdateStewardCommission:
            CHECK_ERROR(readUpdateStewardCommissionTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        default:
            return parser_unexpected_method;
    }

    return  parser_ok;
}
