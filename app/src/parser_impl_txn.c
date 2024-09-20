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
#include "parser_impl_common.h"
#include "parser_txdef.h"
#include "parser_impl_masp.h"
#include "crypto_helper.h"
#include "leb128.h"
#include "bech32.h"
#include "allowed_transactions.h"
#include "txn_validator.h"
#include "txn_delegation.h"
#include "stdbool.h"
#include "parser_address.h"
#include "tx_hash.h"

#include <zxformat.h>

#define DISCRIMINANT_DATA 0x00
#define DISCRIMINANT_EXTRA_DATA 0x01
#define DISCRIMINANT_CODE 0x02
#define DISCRIMINANT_SIGNATURE 0x03
#define DISCRIMINANT_MASP_TX 0x04
#define DISCRIMINANT_MASP_BUILDER 0x05
#define DISCRIMINANT_HEADER 0x06

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

parser_error_t readToken(const AddressAlt *token, const char **symbol) {
    if (token == NULL || symbol == NULL) {
        return parser_unexpected_value;
    }

    // Convert token to address
    char address[53] = {0};
    CHECK_ERROR(crypto_encodeAltAddress(token, address, sizeof(address)))

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

static parser_error_t readInitAccountTxn(const bytes_t *data,const section_t *extra_data,const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    // Pubkey
    v->initAccount.number_of_pubkeys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->initAccount.number_of_pubkeys))
    v->initAccount.pubkeys.ptr = ctx.buffer + ctx.offset;
    v->initAccount.pubkeys.len = 0;
    bytes_t tmpPubkey = {0};
    for (uint32_t i = 0; i < v->initAccount.number_of_pubkeys; i++) {
        CHECK_ERROR(readPubkey(&ctx, &tmpPubkey))
        v->initAccount.pubkeys.len += tmpPubkey.len;
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
            v->initAccount.vp_type_hash.ptr = extra_data[i].bytes_hash;
            v->initAccount.vp_type_hash.len = HASH_LEN;
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
static parser_error_t readPGFInternal(parser_context_t *ctx, pgf_payment_action_t *paymentAction) {
    if (ctx == NULL || paymentAction == NULL) {
        return parser_unexpected_error;
    }

    // Read target
    CHECK_ERROR(readAddressAlt(ctx, &paymentAction->internal.address))
    // Read amount
    paymentAction->internal.amount.len = 32;
    CHECK_ERROR(readBytes(ctx, &paymentAction->internal.amount.ptr, paymentAction->internal.amount.len))

    return parser_ok;
}

static parser_error_t readPGFTargetIBC(parser_context_t *ctx, pgf_payment_action_t *paymentAction) {
    if (ctx == NULL || paymentAction == NULL) {
        return parser_unexpected_error;
    }

    // Read target
    uint32_t tmpValue = 0;
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    paymentAction->ibc.target.len = tmpValue;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.target.ptr, paymentAction->ibc.target.len))

    // Read token amount
    paymentAction->ibc.amount.len = 32;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.amount.ptr, paymentAction->ibc.amount.len))

    // Read port id
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    paymentAction->ibc.portId.len = tmpValue;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.portId.ptr, paymentAction->ibc.portId.len))

    // Read channel id
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    paymentAction->ibc.channelId.len = tmpValue;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.channelId.ptr, paymentAction->ibc.channelId.len))

    return parser_ok;
}

parser_error_t readPGFPaymentAction(parser_context_t *ctx, pgf_payment_action_t *paymentAction) {
    if (ctx == NULL || paymentAction == NULL || ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_error;
    }

    const uint16_t startOffset = ctx->offset;

    CHECK_ERROR(readByte(ctx, (uint8_t*) &paymentAction->action));

    if (paymentAction->action > Retro) {
        return parser_value_out_of_range;
    }

    if (paymentAction->action == Continuous) {
        CHECK_ERROR(readByte(ctx, (uint8_t*) &paymentAction->add_rem));
    }

    CHECK_ERROR(readByte(ctx, (uint8_t*) &paymentAction->targetType));
    switch (paymentAction->targetType) {
        case PGFTargetInternal:
            CHECK_ERROR(readPGFInternal(ctx, paymentAction))
            break;

        case PGFTargetIBC:
            CHECK_ERROR(readPGFTargetIBC(ctx, paymentAction))
            break;

        default:
            return parser_unexpected_error;
    }

    paymentAction->length = ctx->offset - startOffset;
    return parser_ok;
}

static parser_error_t readInitProposalTxn(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    MEMZERO(&v->initProposal, sizeof(v->initProposal));

    // Read content section hash
    v->initProposal.content_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.content_sechash.ptr, v->initProposal.content_sechash.len))

    // Author
    CHECK_ERROR(readAddressAlt(&ctx, &v->initProposal.author))

    // Proposal type
    CHECK_ERROR(readByte(&ctx, &v->initProposal.proposal_type))
    switch (v->initProposal.proposal_type) {
        case Default: {
            break;
        }

        case DefaultWithWasm: {
            v->initProposal.proposal_code_sechash.len = HASH_LEN;
            CHECK_ERROR(readBytes(&ctx, &v->initProposal.proposal_code_sechash.ptr, v->initProposal.proposal_code_sechash.len))
            break;
        }

        case PGFSteward: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_steward_actions_num))
            v->initProposal.pgf_steward_actions.ptr = ctx.buffer + ctx.offset;
            v->initProposal.pgf_steward_actions.len = 0;

            uint8_t add_rem_discriminant = 0;
            AddressAlt tmpBytes;
            for (uint32_t i = 0; i < v->initProposal.pgf_steward_actions_num; i++) {
                CHECK_ERROR(readByte(&ctx, &add_rem_discriminant))
                CHECK_ERROR(readAddressAlt(&ctx, &tmpBytes))
                v->initProposal.pgf_steward_actions.len = ctx.buffer + ctx.offset - v->initProposal.pgf_steward_actions.ptr;
            }
            break;
        }

        case PGFPayment: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_payment_actions_num))
            if (v->initProposal.pgf_payment_actions_num > 0) {
                v->initProposal.pgf_payment_actions.ptr = ctx.buffer + ctx.offset;
                v->initProposal.pgf_payment_actions.len = 0;
                v->initProposal.pgf_payment_ibc_num = 0;
                pgf_payment_action_t tmpPGFPayment = {0};
                for (uint32_t i = 0; i < v->initProposal.pgf_payment_actions_num; i++) {
                    CHECK_ERROR(readPGFPaymentAction(&ctx, &tmpPGFPayment))
                    v->initProposal.pgf_payment_actions.len += tmpPGFPayment.length;
                    if (tmpPGFPayment.targetType == PGFTargetIBC) {
                        v->initProposal.pgf_payment_ibc_num++;
                    }
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

    // Activation epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.activation_epoch))

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
            // MEMCPY(v->initProposal.content_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            v->initProposal.content_hash.ptr = extra_data[i].bytes_hash;
            v->initProposal.content_hash.len = HASH_LEN;
            found_content = true;
        }
        if (v->initProposal.proposal_type == DefaultWithWasm &&
            !memcmp(extraDataHash, v->initProposal.proposal_code_sechash.ptr, HASH_LEN)) {
            // If this section contains the proposal code
            v->initProposal.proposal_code_secidx = extra_data[i].idx;
            v->initProposal.proposal_code_hash.ptr = extra_data[i].bytes_hash;
            v->initProposal.proposal_code_hash.len = HASH_LEN;
            // MEMCPY(v->initProposal.proposal_code_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            found_code = true;
        }
    }

    const bool code_condition = (v->initProposal.proposal_type == DefaultWithWasm) && !found_code;
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

    if (v->voteProposal.proposal_vote > Abstain) {
        return parser_unexpected_value;
    }

    // Voter, should be of length ADDRESS_LEN_BYTES
    CHECK_ERROR(readAddressAlt(&ctx, &v->voteProposal.voter))

    if ((ctx.offset != ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readRevealPubkeyTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Pubkey
    CHECK_ERROR(readPubkey(&ctx, &v->revealPubkey.pubkey))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}



static parser_error_t readWithdrawTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    CHECK_ERROR(readAddressAlt(&ctx, &v->withdraw.validator))

    // Does this tx specify the source
    CHECK_ERROR(readByte(&ctx, &v->withdraw.has_source))

    // Source
    if (v->withdraw.has_source != 0) {
        CHECK_ERROR(readAddressAlt(&ctx, &v->withdraw.source))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readCommissionChangeTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    CHECK_ERROR(readAddressAlt(&ctx, &v->commissionChange.validator))

    // Read new commission rate
    v->commissionChange.new_rate.len = 32;
    CHECK_ERROR(readBytes(&ctx, &v->commissionChange.new_rate.ptr, v->commissionChange.new_rate.len))


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
    CHECK_ERROR(readAddressAlt(&ctx, &v->updateVp.address))

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
    v->updateVp.pubkeys.ptr = ctx.buffer + ctx.offset;
    for (uint32_t i = 0; i < v->updateVp.number_of_pubkeys; i++) {
        bytes_t tmpPubkey = {0};
        CHECK_ERROR(readPubkey(&ctx, &tmpPubkey))
        v->updateVp.pubkeys.len += tmpPubkey.len;
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
            v->updateVp.vp_type_hash.ptr = extra_data[i].bytes_hash;
            v->updateVp.vp_type_hash.len = HASH_LEN;
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

parser_error_t readTransferSourceTarget(parser_context_t *ctx, AddressAlt *owner, AddressAlt *token, bytes_t *amount, uint8_t *amount_denom, const char** symbol) {
    // Source
    CHECK_ERROR(readAddressAlt(ctx, owner))
    // Token
    CHECK_ERROR(readAddressAlt(ctx, token))
    // Get symbol from token
    CHECK_ERROR(readToken(token, symbol))
    // Amount
    amount->len = 32;
    CHECK_ERROR(readBytes(ctx, &amount->ptr, amount->len))
    // Amount denomination
    CHECK_ERROR(readByte(ctx, amount_denom))
    return parser_ok;
}

// Check if the given address is the MASP internal address
bool isMaspInternalAddress(const AddressAlt *addr) {
    return addr->tag == 2 && addr->Internal.tag == 12;
}

static parser_error_t readTransferTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    
    // Number of sources
    CHECK_ERROR(readUint32(&ctx, &v->transfer.sources_len))

    v->transfer.sources.ptr = ctx.buffer + ctx.offset;
    for (uint32_t i = 0; i < v->transfer.sources_len; i++) {
        AddressAlt owner;
        AddressAlt token;
        bytes_t amount;
        uint8_t amount_denom;
        const char* symbol;
        CHECK_ERROR(readTransferSourceTarget(&ctx, &owner, &token, &amount, &amount_denom, &symbol))
        v->transfer.non_masp_sources_len += !isMaspInternalAddress(&owner);
        v->transfer.no_symbol_sources += (symbol == NULL) && !isMaspInternalAddress(&owner);
    }
    v->transfer.sources.len = ctx.buffer + ctx.offset - v->transfer.sources.ptr;

    // Number of targets
    CHECK_ERROR(readUint32(&ctx, &v->transfer.targets_len))

    v->transfer.targets.ptr = ctx.buffer + ctx.offset;
    for (uint32_t i = 0; i < v->transfer.targets_len; i++) {
        AddressAlt owner;
        AddressAlt token;
        bytes_t amount;
        uint8_t amount_denom;
        const char* symbol;
        CHECK_ERROR(readTransferSourceTarget(&ctx, &owner, &token, &amount, &amount_denom, &symbol))
        v->transfer.non_masp_targets_len += !isMaspInternalAddress(&owner);
        v->transfer.no_symbol_targets += (symbol == NULL) && !isMaspInternalAddress(&owner);
    }
    v->transfer.targets.len = ctx.buffer + ctx.offset - v->transfer.targets.ptr;

    // shielded hash, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_shielded_hash))
    if (v->transfer.has_shielded_hash){
        v->transfer.shielded_hash.len = HASH_LEN;
        CHECK_ERROR(readBytes(&ctx,  &v->transfer.shielded_hash.ptr, v->transfer.shielded_hash.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readResignSteward(const bytes_t *data, tx_resign_steward_t *resignSteward) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    CHECK_ERROR(readAddressAlt(&ctx, &resignSteward->steward))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readChangeConsensusKey(const bytes_t *data, tx_consensus_key_change_t *consensusKeyChange) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    CHECK_ERROR(readAddressAlt(&ctx, &consensusKeyChange->validator))
    // Consensus key
    CHECK_ERROR(readPubkey(&ctx, &consensusKeyChange->consensus_key))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readUpdateStewardCommission(const bytes_t *data, tx_update_steward_commission_t *updateStewardCommission) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Address
    CHECK_ERROR(readAddressAlt(&ctx, &updateStewardCommission->steward))

    updateStewardCommission->commissionLen = 0;
    CHECK_ERROR(readUint32(&ctx, &updateStewardCommission->commissionLen))

    updateStewardCommission->commission.ptr = ctx.buffer + ctx.offset;
    const uint16_t startOffset = ctx.offset;
    AddressAlt address;
    bytes_t amount = {.ptr = NULL, .len = 32};
    for (uint32_t i = 0; i < updateStewardCommission->commissionLen; i++) {
        CHECK_ERROR(readAddressAlt(&ctx, &address))
        CHECK_ERROR(readBytes(&ctx, &amount.ptr, amount.len))
    }
    updateStewardCommission->commission.len = ctx.offset - startOffset;

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readChangeValidatorMetadata(const bytes_t *data, tx_metadata_change_t *metadataChange) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    CHECK_ERROR(readAddressAlt(&ctx, &metadataChange->validator))

    uint32_t tmpValue = 0;
    // The validator email
    metadataChange->email.ptr = NULL;
    metadataChange->email.len = 0;
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
      metadataChange->email.len = (uint16_t)tmpValue;
      CHECK_ERROR(readBytes(&ctx, &metadataChange->email.ptr, metadataChange->email.len))
    }

    /// The validator description
    metadataChange->description.ptr = NULL;
    metadataChange->description.len = 0;
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
        metadataChange->description.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->description.ptr, metadataChange->description.len))
    }

    /// The validator website
    metadataChange->website.ptr = NULL;
    metadataChange->website.len = 0;
    uint8_t has_website;
    CHECK_ERROR(readByte(&ctx, &has_website))
    if (has_website) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->website.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->website.ptr, metadataChange->website.len))
    }

    /// The validator's discord handle
    metadataChange->discord_handle.ptr = NULL;
    metadataChange->discord_handle.len = 0;
    uint8_t has_discord_handle;
    CHECK_ERROR(readByte(&ctx, &has_discord_handle))
    if (has_discord_handle) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->discord_handle.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->discord_handle.ptr, metadataChange->discord_handle.len))
    }

    /// The validator's avatar
    metadataChange->avatar.ptr = NULL;
    metadataChange->avatar.len = 0;
    uint8_t has_avatar;
    CHECK_ERROR(readByte(&ctx, &has_avatar))
    if (has_avatar) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->avatar.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->avatar.ptr, metadataChange->avatar.len))
    }

        /// The validator's name
    metadataChange->name.ptr = NULL;
    metadataChange->name.len = 0;
    uint8_t has_name;
    CHECK_ERROR(readByte(&ctx, &has_name))
    if (has_name) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->name.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->name.ptr, metadataChange->name.len))
    }

    // Commission rate
    CHECK_ERROR(readByte(&ctx, &metadataChange->has_commission_rate))
    if (metadataChange->has_commission_rate) {
        metadataChange->commission_rate.len = 32;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->commission_rate.ptr, metadataChange->commission_rate.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readBridgePoolTransfer(const bytes_t *data, tx_bridge_pool_transfer_t *bridgePoolTransfer) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    CHECK_ERROR(readByte(&ctx, &bridgePoolTransfer->kind))
    if (bridgePoolTransfer->kind > Nut) {
         return parser_value_out_of_range;
    }

    bridgePoolTransfer->asset.len = ETH_ADDRESS_LEN;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->asset.ptr, bridgePoolTransfer->asset.len))

    bridgePoolTransfer->recipient.len = ETH_ADDRESS_LEN;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->recipient.ptr, bridgePoolTransfer->recipient.len))

    CHECK_ERROR(readAddressAlt(&ctx, &bridgePoolTransfer->sender))

    bridgePoolTransfer->amount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->amount.ptr, bridgePoolTransfer->amount.len))

    bridgePoolTransfer->gasAmount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->gasAmount.ptr, bridgePoolTransfer->gasAmount.len))

    CHECK_ERROR(readAddressAlt(&ctx, &bridgePoolTransfer->gasPayer))

    CHECK_ERROR(readAddressAlt(&ctx, &bridgePoolTransfer->gasToken))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readTimestamp(parser_context_t *ctx, timestamp_t *timestamp, uint8_t expected_tag) {
    uint8_t consumed = 0;
    uint64_t tmp = 0;

    CHECK_ERROR(checkTag(ctx, expected_tag))
    const uint64_t timestampSize = ctx->bufferLen - ctx->offset;
    decodeLEB128(ctx->buffer + ctx->offset, timestampSize, &consumed, &tmp);
    ctx->offset += consumed;

    const uint32_t e9 = 1000000000;
    timestamp->millis = tmp / e9;
    timestamp->nanos = (uint32_t)(tmp - timestamp->millis*e9);

    return parser_ok;
}

__Z_INLINE parser_error_t readSenderAndReceiver(parser_context_t *ctx, parser_tx_t *v, uint8_t sender_expected_tag, uint8_t reveiver_expected_tag ) {
    // Read sender
    CTX_CHECK_AVAIL(ctx, 1);
    if (*(ctx->buffer + ctx->offset) == sender_expected_tag) {
        CHECK_ERROR(checkTag(ctx, sender_expected_tag))
        CHECK_ERROR(readFieldSizeU16(ctx, &v->ibc.sender_address.len))
        CHECK_ERROR(readBytes(ctx, &v->ibc.sender_address.ptr, v->ibc.sender_address.len))
    }

    // Read receiver
    CTX_CHECK_AVAIL(ctx, 1);
    if (*(ctx->buffer + ctx->offset) == reveiver_expected_tag) {
        CHECK_ERROR(checkTag(ctx, reveiver_expected_tag))
        CHECK_ERROR(readFieldSizeU16(ctx, &v->ibc.receiver.len))
        CHECK_ERROR(readBytes(ctx, &v->ibc.receiver.ptr, v->ibc.receiver.len))
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readTimeouts(parser_context_t *ctx, parser_tx_t *v, uint8_t height_expected_tag, uint8_t timestamp_expected_tag ) {
    // Read timeout height
    CHECK_ERROR(checkTag(ctx, height_expected_tag))
    CHECK_ERROR(readByte(ctx, &v->ibc.timeout_height_type))

    if (v->ibc.timeout_height_type > 0) {
        uint8_t consumed = 0;
        uint64_t tmp = 0;

        // Read 0x08
        CHECK_ERROR(checkTag(ctx, 0x08))
        const uint64_t remainingBytes = ctx->bufferLen - ctx->offset;
        decodeLEB128(ctx->buffer + ctx->offset, remainingBytes, &consumed, &tmp);
        v->ibc.revision_number = tmp;
        ctx->offset += consumed;

        CHECK_ERROR(checkTag(ctx, 0x10))
        const uint64_t remainingBytes2 = ctx->bufferLen - ctx->offset;
        decodeLEB128(ctx->buffer + ctx->offset, remainingBytes2, &consumed, &tmp);
        v->ibc.revision_height = tmp;
        ctx->offset += consumed;
    }

    // Read timeout timestamp
    CHECK_ERROR(readTimestamp(ctx, &v->ibc.timeout_timestamp, timestamp_expected_tag))
    return parser_ok;
}

static parser_error_t readIBCTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    v->ibc.is_ibc = 1;
    uint32_t tmpValue;
    uint16_t tmpFieldLen = 0;
    CHECK_ERROR(readUint32(&ctx, &tmpValue));

    // Read port id
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.port_id.len))
    CHECK_ERROR(readBytes(&ctx, &v->ibc.port_id.ptr, v->ibc.port_id.len))

    // Read channel id
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.channel_id.len))
    CHECK_ERROR(readBytes(&ctx, &v->ibc.channel_id.ptr, v->ibc.channel_id.len))

    ////// Packed data
    CHECK_ERROR(checkTag(&ctx, 0x1A))
    CHECK_ERROR(readFieldSizeU16(&ctx, &tmpFieldLen))

    uint8_t tag = 0;
    CHECK_ERROR(readByte(&ctx, &tag))

    if (tag == 0x0A) { // Transfer
        CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.token_address.len))
        CHECK_ERROR(readBytes(&ctx, &v->ibc.token_address.ptr, v->ibc.token_address.len))

        // Read token amount
        CHECK_ERROR(checkTag(&ctx, 0x12))
        CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.token_amount.len))
        CHECK_ERROR(readBytes(&ctx, &v->ibc.token_amount.ptr, v->ibc.token_amount.len))

        CHECK_ERROR(readSenderAndReceiver(&ctx, v, 0x22, 0x2A))
        CHECK_ERROR(readTimeouts(&ctx, v, 0x32, 0x38))

    } else { // NFT Transfer
        v->ibc.is_nft = 1;

        // Read ClassId
        ctx.offset--;
        v->ibc.class_id.len = tmpFieldLen;
        CHECK_ERROR(readBytes(&ctx, &v->ibc.class_id.ptr, v->ibc.class_id.len))

        // Read TokenIDs
        uint16_t tmp_len = 0;
        v->ibc.token_id.ptr = ctx.buffer + ctx.offset;
        while (*(ctx.buffer + ctx.offset) == 0x22) {
            ctx.offset++;
            CHECK_ERROR(readFieldSizeU16(&ctx, &tmp_len))
            CTX_CHECK_AND_ADVANCE(&ctx, tmp_len);
            v->ibc.n_token_id++;
        }

        v->ibc.token_id.len = ctx.buffer + ctx.offset - v->ibc.token_id.ptr;

        CHECK_ERROR(readSenderAndReceiver(&ctx, v, 0x2a, 0x32))
        CHECK_ERROR(readTimeouts(&ctx, v, 0x3a, 0x40))
    }

    // Read memo if present
    uint8_t tmp_byte = 0;
    uint8_t has_transfer = 0;
    CHECK_ERROR(readByte(&ctx, &tmp_byte))
    if (tmp_byte == 0x42 || tmp_byte == 0x4a) {
        CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.memo.len))
        CHECK_ERROR(readBytes(&ctx, &v->ibc.memo.ptr, v->ibc.memo.len))

        // Read byte indicating presence of Transfer
        CHECK_ERROR(readByte(&ctx, &has_transfer))
    }

    if(has_transfer || tmp_byte == 1) {
        // Number of sources
        CHECK_ERROR(readUint32(&ctx, &v->ibc.transfer.sources_len))

        v->ibc.transfer.sources.ptr = ctx.buffer + ctx.offset;
        for (uint32_t i = 0; i < v->ibc.transfer.sources_len; i++) {
            AddressAlt owner;
            AddressAlt token;
            bytes_t amount;
            uint8_t amount_denom;
            const char* symbol;
            CHECK_ERROR(readTransferSourceTarget(&ctx, &owner, &token, &amount, &amount_denom, &symbol))
            v->ibc.transfer.non_masp_sources_len += !isMaspInternalAddress(&owner);
            v->ibc.transfer.no_symbol_sources += (symbol == NULL) && !isMaspInternalAddress(&owner);
        }
        v->ibc.transfer.sources.len = ctx.buffer + ctx.offset - v->ibc.transfer.sources.ptr;

        // Number of targets
        CHECK_ERROR(readUint32(&ctx, &v->ibc.transfer.targets_len))

        v->ibc.transfer.targets.ptr = ctx.buffer + ctx.offset;
        for (uint32_t i = 0; i < v->ibc.transfer.targets_len; i++) {
            AddressAlt owner;
            AddressAlt token;
            bytes_t amount;
            uint8_t amount_denom;
            const char* symbol;
            CHECK_ERROR(readTransferSourceTarget(&ctx, &owner, &token, &amount, &amount_denom, &symbol))
            v->ibc.transfer.non_masp_targets_len += !isMaspInternalAddress(&owner);
            v->ibc.transfer.no_symbol_targets += (symbol == NULL) && !isMaspInternalAddress(&owner);
        }
        v->ibc.transfer.targets.len = ctx.buffer + ctx.offset - v->ibc.transfer.targets.ptr;

        // shielded hash, check if it is there
        CHECK_ERROR(readByte(&ctx, &v->ibc.transfer.has_shielded_hash))
        if (v->ibc.transfer.has_shielded_hash){
            v->ibc.transfer.shielded_hash.len = HASH_LEN;
            CHECK_ERROR(readBytes(&ctx,  &v->ibc.transfer.shielded_hash.ptr, v->ibc.transfer.shielded_hash.len))
        }
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
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

    // Batch length
    CHECK_ERROR(readUint32(ctx, &v->transaction.header.batchLen))
    // Only singleton batches are supported currently
    if (v->transaction.header.batchLen != 1) {
        return parser_unexpected_value;
    }

    // Code hash
    v->transaction.header.codeHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // Data hash
    v->transaction.header.dataHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))

    // Memo hash
    v->transaction.header.memoHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.memoHash.ptr, v->transaction.header.memoHash.len))

    // Atomic
    CHECK_ERROR(readByte(ctx, &v->transaction.header.atomic))

    v->transaction.header.bytes.len = ctx->offset - tmpOffset;

    CHECK_ERROR(checkTag(ctx, 0x01))
    // Fee.amount
    v->transaction.header.fees.amount.len = 32;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.amount.ptr, v->transaction.header.fees.amount.len))
    // Fee.denom
    CHECK_ERROR(readByte(ctx, &v->transaction.header.fees.denom))

    // Fee.address
    CHECK_ERROR(readAddressAlt(ctx, &v->transaction.header.fees.address))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transaction.header.fees.address, &v->transaction.header.fees.symbol))

    // Pubkey
    if (ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }
    const uint8_t pkType = *(ctx->buffer + ctx->offset);
    //Pubkey must include pkType (needed for encoding)
    v->transaction.header.pubkey.len = 1 + (pkType == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN);
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.pubkey.ptr, v->transaction.header.pubkey.len))

    // GasLimit
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.gasLimit))

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
        uint32_t bytesLen = 0;
        CHECK_ERROR(readUint32(ctx, &bytesLen));
        if (bytesLen > UINT16_MAX) {
             return parser_value_out_of_range;
        }
        extraData->bytes.len = (uint16_t)bytesLen;
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
        signature->addressBytes.ptr = ctx->buffer + ctx->offset;
        CHECK_ERROR(readAddressAlt(ctx, &signature->address))
        signature->addressBytes.len = ctx->buffer + ctx->offset - signature->addressBytes.ptr;
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
    return parser_ok;
}

parser_error_t readSections(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readUint32(ctx, &v->transaction.sections.sectionLen))

    if (v->transaction.sections.sectionLen > 7) {
        return parser_invalid_output_buffer;
    }
    v->transaction.isMasp = false;
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
#if defined(COMPILE_MASP)
            case DISCRIMINANT_MASP_TX:
                // Identify tx has masp tx
                v->transaction.isMasp = true;
                CHECK_ERROR(readMaspTx(ctx, &v->transaction.sections.maspTx))
                v->transaction.maspTx_idx = i+1;
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
        const section_t *extra_data = txObj->transaction.sections.extraData;
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
        if (txObj->transaction.header.memoSection == NULL) {
            return parser_unexpected_error;
        }
    }

    CHECK_ERROR(readTransactionType(&txObj->transaction.sections.code.tag, &txObj->typeTx))
    const section_t *data = &txObj->transaction.sections.data;
    switch (txObj->typeTx) {
        case Bond:
        case Unbond:
            CHECK_ERROR(readBondUnbond(&txObj->transaction.sections.data.bytes, txObj))
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
        case ClaimRewards:
        case Withdraw:
            CHECK_ERROR(readWithdrawTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case CommissionChange:
            CHECK_ERROR(readCommissionChangeTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case BecomeValidator:
            CHECK_ERROR(readBecomeValidator(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UpdateVP:
            CHECK_ERROR(readUpdateVPTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UnjailValidator:
            CHECK_ERROR(readUnjailValidator(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case IBC:
            CHECK_ERROR(readIBCTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ReactivateValidator:
        case DeactivateValidator:
            CHECK_ERROR(readActivateValidator(&data->bytes, &txObj->activateValidator))
            break;
        case Redelegate:
            CHECK_ERROR(readRedelegate(&data->bytes, &txObj->redelegation))
            break;

        case ResignSteward:
            CHECK_ERROR(readResignSteward(&data->bytes, &txObj->resignSteward))
            break;

        case ChangeConsensusKey:
            CHECK_ERROR(readChangeConsensusKey(&data->bytes, &txObj->consensusKeyChange))
            break;

        case UpdateStewardCommission:
            CHECK_ERROR(readUpdateStewardCommission(&data->bytes, &txObj->updateStewardCommission))
            break;

        case ChangeValidatorMetadata:
            CHECK_ERROR(readChangeValidatorMetadata(&data->bytes, &txObj->metadataChange))
            break;

        case BridgePoolTransfer:
            CHECK_ERROR(readBridgePoolTransfer(&data->bytes, &txObj->bridgePoolTransfer))
            break;

        default:
            return parser_unexpected_method;
    }

    return  parser_ok;
}

parser_error_t verifyShieldedHash(parser_context_t *ctx) {
    if (ctx == NULL) {
        return parser_unexpected_error;
    }

#if defined(LEDGER_SPECIFIC)
    // compute tx_id hash
    uint8_t tx_id_hash[HASH_LEN] = {0};
    if (tx_hash_txId(ctx->tx_obj, tx_id_hash) != zxerr_ok) {
        return parser_unexpected_error;
    }

    if (ctx->tx_obj->transaction.sections.maspBuilder.target_hash.len == HASH_LEN) {
        if (memcmp(tx_id_hash, ctx->tx_obj->transaction.sections.maspBuilder.target_hash.ptr, HASH_LEN) != 0) {
            return parser_invalid_target_hash;
        }
    }

    if (ctx->tx_obj->transfer.has_shielded_hash && memcmp(ctx->tx_obj->transfer.shielded_hash.ptr, tx_id_hash, HASH_LEN) != 0) {
        return parser_invalid_target_hash;
    }

    if(ctx->tx_obj->ibc.transfer.has_shielded_hash && memcmp(ctx->tx_obj->ibc.transfer.shielded_hash.ptr, tx_id_hash, HASH_LEN) != 0) {
        return parser_invalid_target_hash;
    }
#endif

    return parser_ok;
}
