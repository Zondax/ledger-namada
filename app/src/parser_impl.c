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
#include "parser_impl.h"
#include "zxformat.h"
#include "leb128.h"
#include "app_mode.h"

#include "parser_impl_common.h"

parser_error_t _read(parser_context_t *ctx, parser_tx_t *v) {

    CHECK_ERROR(readHeader(ctx, v))
    CHECK_ERROR(readSections(ctx, v))

    CHECK_ERROR(validateTransactionParams(v))

    if(ctx->tx_obj->transaction.isMasp || ctx->tx_obj->ibc.is_ibc) {
        CHECK_ERROR(verifyShieldedHash(ctx))
    }

    if (ctx->offset != ctx->bufferLen) {
        return parser_unexpected_unparsed_bytes;
    }

    return parser_ok;
}

parser_error_t getNumItems(const parser_context_t *ctx, uint8_t *numItems) {
    *numItems = 0;
    switch (ctx->tx_obj->typeTx) {
        case Unbond:
        case Bond:
            *numItems = (app_mode_expert() ? BOND_EXPERT_PARAMS : BOND_NORMAL_PARAMS) + ctx->tx_obj->bond.has_source;
            break;

        case Custom:
            *numItems = (app_mode_expert() ? CUSTOM_EXPERT_PARAMS : CUSTOM_NORMAL_PARAMS);
            break;

        case Transfer:
            if(ctx->tx_obj->transaction.isMasp) {
                uint8_t items = 1;
                items += 3 * ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.n_outputs; // print from outputs
                items += 3 * ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.n_spends; // print from spends

                *numItems = (app_mode_expert() ? items + 4 : items);
            } else {
                *numItems = (app_mode_expert() ? TRANSFER_EXPERT_PARAMS : TRANSFER_NORMAL_PARAMS);
            }
            (*numItems) += ctx->tx_obj->transfer.non_masp_sources_len*2 + ctx->tx_obj->transfer.non_masp_targets_len*2 + ctx->tx_obj->transfer.no_symbol_sources + ctx->tx_obj->transfer.no_symbol_targets;
            break;

        case InitAccount: {
            const uint32_t pubkeys_num = ctx->tx_obj->initAccount.number_of_pubkeys;
            *numItems = (uint8_t)((app_mode_expert() ? INIT_ACCOUNT_EXPERT_PARAMS : INIT_ACCOUNT_NORMAL_PARAMS) + pubkeys_num);
            break;
        }
        case InitProposal: {
            *numItems = (app_mode_expert() ? INIT_PROPOSAL_EXPERT_PARAMS : INIT_PROPOSAL_NORMAL_PARAMS);
            if (ctx->tx_obj->initProposal.proposal_type == DefaultWithWasm) {
                (*numItems)++;
            } else if (ctx->tx_obj->initProposal.proposal_type == PGFSteward) {
                *numItems += ctx->tx_obj->initProposal.pgf_steward_actions_num;
            } else if (ctx->tx_obj->initProposal.proposal_type == PGFPayment) {
                *numItems += 3 * ctx->tx_obj->initProposal.pgf_payment_actions_num + 2 * ctx->tx_obj->initProposal.pgf_payment_ibc_num;
            }
            break;
        }
        case VoteProposal: {
            *numItems = (uint8_t) (app_mode_expert() ? VOTE_PROPOSAL_EXPERT_PARAMS : VOTE_PROPOSAL_NORMAL_PARAMS);
            break;
        }
        case RevealPubkey:
            *numItems = (app_mode_expert() ? REVEAL_PUBKEY_EXPERT_PARAMS : REVEAL_PUBKEY_NORMAL_PARAMS);
            break;

        case Withdraw:
            *numItems = (app_mode_expert() ? WITHDRAW_EXPERT_PARAMS : WITHDRAW_NORMAL_PARAMS) + ctx->tx_obj->withdraw.has_source;
            break;

        case CommissionChange:
            *numItems = (app_mode_expert() ? COMMISSION_CHANGE_EXPERT_PARAMS : COMMISSION_CHANGE_NORMAL_PARAMS);
            break;

        case BecomeValidator: {
            *numItems = (app_mode_expert() ? BECOME_VALIDATOR_EXPERT_PARAMS : BECOME_VALIDATOR_NORMAL_PARAMS);
            if(ctx->tx_obj->becomeValidator.name.ptr) {
                (*numItems)++;
            }
            if(ctx->tx_obj->becomeValidator.description.ptr) {
                (*numItems)++;
            }
            if(ctx->tx_obj->becomeValidator.discord_handle.ptr) {
                (*numItems)++;
            }
            if(ctx->tx_obj->becomeValidator.website.ptr) {
                (*numItems)++;
            }
            if(ctx->tx_obj->becomeValidator.avatar.ptr) {
                (*numItems)++;
            }
            break;
        }
        case UpdateVP: {
            const uint32_t pubkeys_num = ctx->tx_obj->updateVp.number_of_pubkeys;
            const uint8_t has_threshold = ctx->tx_obj->updateVp.has_threshold;
            const uint8_t has_vp_code = ctx->tx_obj->updateVp.has_vp_code;
            *numItems = (uint8_t) ((app_mode_expert() ? UPDATE_VP_EXPERT_PARAMS : UPDATE_VP_NORMAL_PARAMS) + pubkeys_num + has_threshold + has_vp_code);
            break;
        }

        case ReactivateValidator:
        case DeactivateValidator:
        case UnjailValidator:
            *numItems = (app_mode_expert() ? UNJAIL_VALIDATOR_EXPERT_PARAMS : UNJAIL_VALIDATOR_NORMAL_PARAMS);
            break;

        case IBC:
            *numItems = (app_mode_expert() ?  IBC_EXPERT_PARAMS : IBC_NORMAL_PARAMS);
            if(ctx->tx_obj->transaction.isMasp) {
                *numItems += 3 * ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.n_outputs; // print from outputs
                *numItems += 3 * ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.n_spends; // print from spends
            }
            *numItems += ctx->tx_obj->ibc.transfer.non_masp_sources_len*2 + ctx->tx_obj->ibc.transfer.non_masp_targets_len*2 + ctx->tx_obj->ibc.transfer.no_symbol_sources + ctx->tx_obj->ibc.transfer.no_symbol_targets;
            *numItems += ctx->tx_obj->ibc.memo.len > 0 && app_mode_expert();
            if(ctx->tx_obj->ibc.is_nft) {
                *numItems += ctx->tx_obj->ibc.n_token_id;
            }
            break;

        case Redelegate:
            *numItems = (app_mode_expert() ? REDELEGATE_EXPERT_PARAMS : REDELEGATE_NORMAL_PARAMS);
            break;

        case ClaimRewards:
            *numItems = (app_mode_expert() ? CLAIM_REWARDS_EXPERT_PARAMS : CLAIM_REWARDS_NORMAL_PARAMS) + ctx->tx_obj->withdraw.has_source;
            break;

        case ResignSteward:
            *numItems = (app_mode_expert() ? RESIGN_STEWARD_EXPERT_PARAMS : RESIGN_STEWARD_NORMAL_PARAMS);
            break;

        case ChangeConsensusKey:
            *numItems = (app_mode_expert() ? CHANGE_CONSENSUS_KEY_EXPERT_PARAMS : CHANGE_CONSENSUS_KEY_NORMAL_PARAMS);
            break;

        case UpdateStewardCommission:
            *numItems = (app_mode_expert() ? UPDATE_STEWARD_COMMISSION_EXPERT_PARAMS : UPDATE_STEWARD_COMMISSION_NORMAL_PARAMS) + 2 * ctx->tx_obj->updateStewardCommission.commissionLen;
            break;

        case ChangeValidatorMetadata: {
            *numItems = app_mode_expert() ? CHANGE_VALIDATOR_METADATA_EXPERT_PARAMS : CHANGE_VALIDATOR_METADATA_NORMAL_PARAMS;

            if (ctx->tx_obj->metadataChange.name.ptr != NULL) {
                (*numItems)++;
            }
            if (ctx->tx_obj->metadataChange.email.ptr != NULL) {
                (*numItems)++;
            }
            if (ctx->tx_obj->metadataChange.description.ptr != NULL) {
                (*numItems)++;
            }
            if (ctx->tx_obj->metadataChange.website.ptr != NULL) {
                (*numItems)++;
            }
            if (ctx->tx_obj->metadataChange.discord_handle.ptr != NULL) {
                (*numItems)++;
            }
            if (ctx->tx_obj->metadataChange.avatar.ptr != NULL) {
                (*numItems)++;
            }
            if (ctx->tx_obj->metadataChange.has_commission_rate) {
                (*numItems)++;
            }

            break;
        }

        case BridgePoolTransfer:
            *numItems = app_mode_expert() ? BRIDGE_POOL_TRANSFER_EXPERT_PARAMS : BRIDGE_POOL_TRANSFER_NORMAL_PARAMS;
            break;

        default:
            break;
    }

    if (ctx->tx_obj->transaction.header.memoSection != NULL) {
      (*numItems)++;
    }

    if(app_mode_expert() && ctx->tx_obj->transaction.header.fees.symbol == NULL) {
        (*numItems)++;
    }

    if(*numItems == 0) {
        return parser_unexpected_number_items;
    }
    return parser_ok;
}


const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_missing_field:
            return "missing field";

        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";
        case parser_decimal_too_big:
            return "decimal cannot be parsed";
        case parser_invalid_output_buffer:
            return "invalid output buffer";
        default:
            return "Unrecognized error code";
    }
}
