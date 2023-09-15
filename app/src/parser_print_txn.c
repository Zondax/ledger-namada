/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
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
#include "parser_print_common.h"
#include "parser_impl_common.h"
#include "app_mode.h"
#include <zxmacros.h>
#include <zxformat.h>
#include "coin.h"
#include "timeutils.h"

static parser_error_t printBondTxn( const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    // Bump displayIdx if source is not present
    if (ctx->tx_obj->bond.has_source == 0 && displayIdx >= 1) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Bond");
            if (ctx->tx_obj->typeTx == Unbond) {
                snprintf(outVal, outValLen, "Unbond");
            }
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            if (ctx->tx_obj->bond.has_source == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Source");
            CHECK_ERROR(printAddress(ctx->tx_obj->bond.source, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->bond.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(&ctx->tx_obj->bond.amount, COIN_AMOUNT_DECIMAL_PLACES, COIN_TICKER,
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 4;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printTransferTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Transfer");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Sender");
            CHECK_ERROR(printAddress(ctx->tx_obj->transfer.source_address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Destination");
            CHECK_ERROR(printAddress(ctx->tx_obj->transfer.target_address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(&ctx->tx_obj->transfer.amount, ctx->tx_obj->transfer.amount_denom,
                                    ctx->tx_obj->transfer.symbol,
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 4;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printCustomTxn( const parser_context_t *ctx,
                                           uint8_t displayIdx,
                                           char *outKey, uint16_t outKeyLen,
                                           char *outVal, uint16_t outValLen,
                                           uint8_t pageIdx, uint8_t *pageCount) {

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Custom");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 1;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printInitAccountTxn(  const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    const tx_init_account_t *initAccount = &ctx->tx_obj->initAccount;

    // Since every account key entry will be considered as a different field, we adjust the display index.
    const uint32_t pubkeys_num = initAccount->number_of_pubkeys;
    const uint8_t pubkeys_first_field_idx = 1;
    const uint8_t adjustedDisplayIdx = \
        (displayIdx < pubkeys_first_field_idx) \
            ? displayIdx
            : ((displayIdx < pubkeys_first_field_idx + pubkeys_num) \
                ? pubkeys_first_field_idx
                : displayIdx - pubkeys_num + 1);

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Account");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
        {
            if (pubkeys_num == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Public key");
            const uint8_t key_index = displayIdx - pubkeys_first_field_idx;
            const bytes_t key = {
                .ptr = initAccount->pubkeys.ptr + PUBKEY_BYTES_LEN * key_index,
                .len = PUBKEY_BYTES_LEN
            };
            CHECK_ERROR(printPubkey(key, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 2:
        {
            snprintf(outKey, outKeyLen, "Threshold");
            // Threshold value is less than 3 characters (uint8)
            char strThreshold[3] = {0};
            if (uint64_to_str(strThreshold, sizeof(strThreshold), initAccount->threshold) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strThreshold, pageIdx, pageCount);
            break;
        }
        case 3:
            snprintf(outKey, outKeyLen, "VP type");
            pageString(outVal, outValLen,ctx->tx_obj->initAccount.vp_type_text, pageIdx, pageCount);
            if (app_mode_expert()) {
                CHECK_ERROR(printVPTypeHash(&ctx->tx_obj->initAccount.vp_type_hash,
                                            outVal, outValLen, pageIdx, pageCount))
            }
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 3 + pubkeys_num;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printInitProposalTxn(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    // Bump displayIdx if ID is not present
    if (ctx->tx_obj->initProposal.has_id == 0 && displayIdx >= 1) {
        displayIdx++;
    }

    // Less than 20 characters are epochs are uint64
    char strEpoch[20] = {0};
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init proposal");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            if (ctx->tx_obj->initProposal.has_id == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "ID");
            // Less than 20 characters as proposal_id is an Option<u64>
            char idString[20] = {0};
            if (uint64_to_str(idString, sizeof(idString), ctx->tx_obj->initProposal.proposal_id) != NULL)
            {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, idString, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Proposal type");
            if (ctx->tx_obj->initProposal.proposal_type == 0 && ctx->tx_obj->initProposal.has_proposal_code == 0) {
                snprintf(outVal, outValLen, "Default");
            } else if (ctx->tx_obj->initProposal.proposal_type == 0 && ctx->tx_obj->initProposal.has_proposal_code == 1) {
                const bytes_t *codeHash = &ctx->tx_obj->initProposal.proposal_code_hash;
                pageStringHex(outVal, outValLen, (const char*)codeHash->ptr, codeHash->len, pageIdx, pageCount);
            } else if (ctx->tx_obj->initProposal.proposal_type == 1) {
                snprintf(outVal, outValLen, "PGF Steward");
            } else if (ctx->tx_obj->initProposal.proposal_type == 2) {
                snprintf(outVal, outValLen, "PGF Payment");
            } else {
                return parser_unexpected_error;
            }
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Author");
            CHECK_ERROR(printAddress(ctx->tx_obj->initProposal.author, outVal, outValLen, pageIdx, pageCount))
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Voting start epoch");
            if (uint64_to_str(strEpoch, sizeof(strEpoch), ctx->tx_obj->initProposal.voting_start_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strEpoch, pageIdx, pageCount);
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Voting end epoch");
            if (uint64_to_str(strEpoch, sizeof(strEpoch), ctx->tx_obj->initProposal.voting_end_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strEpoch, pageIdx, pageCount);
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Grace epoch");
            if (uint64_to_str(strEpoch, sizeof(strEpoch), ctx->tx_obj->initProposal.grace_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strEpoch, pageIdx, pageCount);
            break;
        case 7:
            snprintf(outKey, outKeyLen, "Content");
            char strContent[65] = {0};
            const bytes_t *content = &ctx->tx_obj->initProposal.content_hash;
            array_to_hexstr((char*) strContent, sizeof(strContent), content->ptr, content->len);
            pageString(outVal, outValLen, (const char*) &strContent, pageIdx, pageCount);
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 8;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printVoteProposalTxn(const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    const tx_vote_proposal_t *voteProposal = &ctx->tx_obj->voteProposal;

    const uint32_t delegations_num = voteProposal->number_of_delegations;
    const uint8_t delegations_first_field_idx = 4;
    const uint8_t adjustedDisplayIdx = \
        (displayIdx < delegations_first_field_idx) \
            ? displayIdx
            : ((displayIdx < delegations_first_field_idx + delegations_num) \
                ? delegations_first_field_idx
                : displayIdx - delegations_num + 1);

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Vote Proposal");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "ID");
            // Less than 20 characters as proposal_id is an Option<u64>
            char strId[20] = {0};
            if (uint64_to_str(strId, sizeof(strId), voteProposal->proposal_id) != NULL ) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strId, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Vote");
            if (voteProposal->proposal_vote == Yay) {
                switch (voteProposal->vote_type) {
                    case Default:
                        snprintf(outVal, outValLen, "yay");
                        break;
                    case PGFSteward:
                        snprintf(outVal, outValLen, "yay for PGF steward");
                        break;
                    case PGFPayment:
                        snprintf(outVal, outValLen, "yay for PGF payment");
                        break;
                    default:
                        return parser_unexpected_value;
                }
            } else {
                snprintf(outVal, outValLen, "nay");
            }
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Voter");
            CHECK_ERROR(printAddress(voteProposal->voter, outVal, outValLen, pageIdx, pageCount))
            break;
        case 4: {
            if (voteProposal->number_of_delegations == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Delegation");
            const uint8_t address_index = displayIdx - delegations_first_field_idx;
            const bytes_t address = {
                .ptr = voteProposal->delegations.ptr + ADDRESS_LEN_BYTES * address_index,
                .len = ADDRESS_LEN_BYTES
            };
            CHECK_ERROR(printAddress(address, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 4 + delegations_num;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printRevealPubkeyTxn(const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Reveal Pubkey");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Public key");
            CHECK_ERROR(printPubkey(ctx->tx_obj->revealPubkey.pubkey, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 2;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printUnjailValidatorTxn(const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Unjail Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->unjailValidator.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 2;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printUpdateVPTxn(const parser_context_t *ctx,
                                       uint8_t displayIdx,
                                       char *outKey, uint16_t outKeyLen,
                                       char *outVal, uint16_t outValLen,
                                       uint8_t pageIdx, uint8_t *pageCount) {
    const tx_update_vp_t *updateVp = &ctx->tx_obj->updateVp;

    const uint32_t pubkeys_num = updateVp->number_of_pubkeys;
    // Since every account key entry will be considered as a different field, we adjust the display index.
    const uint8_t pubkeys_first_field_idx = 2;
    uint8_t adjustedDisplayIdx = \
        (displayIdx < pubkeys_first_field_idx) \
            ? displayIdx
            : ((displayIdx < pubkeys_first_field_idx + pubkeys_num) \
                ? pubkeys_first_field_idx
                : displayIdx - pubkeys_num + 1);

    // Bump adjustedDisplayIdx if threshold is not present
    if (adjustedDisplayIdx >= 3 && !updateVp->has_threshold) {
        adjustedDisplayIdx++;
    }

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Update VP");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Address");
            CHECK_ERROR(printAddress(ctx->tx_obj->updateVp.address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
        {
            if (pubkeys_num == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Public key");
            const uint8_t key_index = displayIdx - pubkeys_first_field_idx;
            const bytes_t key = {
                .ptr = updateVp->pubkeys.ptr + PUBKEY_BYTES_LEN * key_index,
                .len = PUBKEY_BYTES_LEN
            };
            CHECK_ERROR(printPubkey(key, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 3:
        {
            if (updateVp->has_threshold) {
                snprintf(outKey, outKeyLen, "Threshold");
                // Threshold value is less than 3 characters (uint8)
                char strThreshold[3] = {0};
                if (uint64_to_str(strThreshold, sizeof(strThreshold), updateVp->threshold) != NULL) {
                    return parser_unexpected_error;
                }
                pageString(outVal, outValLen, strThreshold, pageIdx, pageCount);
            }
            break;
        }
        case 4:
            snprintf(outKey, outKeyLen, "VP type");
            pageString(outVal, outValLen,ctx->tx_obj->updateVp.vp_type_text, pageIdx, pageCount);
            if (app_mode_expert()) {
                CHECK_ERROR(printVPTypeHash(&ctx->tx_obj->updateVp.vp_type_hash,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 4 + pubkeys_num - (updateVp->has_threshold ? 0 : 1);
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printInitValidatorTxn(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    char hexString[205] = {0};
    const tx_init_validator_t *initValidator = &ctx->tx_obj->initValidator;

    const uint32_t account_keys_num = initValidator->number_of_account_keys; 

    // Since every account key entry will be considered as a different field, we adjust the display index.
    const uint8_t account_keys_first_field_idx = 1;
    const uint8_t adjustedDisplayIdx = \
        (displayIdx < account_keys_first_field_idx) \
            ? displayIdx
            : ((displayIdx < account_keys_first_field_idx + account_keys_num) \
                ? account_keys_first_field_idx
                : displayIdx - account_keys_num + 1);

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
        {
            if (account_keys_num == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Account key");
            const uint8_t key_index = displayIdx - account_keys_first_field_idx;
            const bytes_t key = {
                .ptr = initValidator->account_keys.ptr + PUBKEY_BYTES_LEN * key_index,
                .len = PUBKEY_BYTES_LEN
            };
            CHECK_ERROR(printPubkey(key, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 2:
        {
            snprintf(outKey, outKeyLen, "Threshold");
            // Threshold value is less than 3 characters (uint8)
            char strThreshold[3] = {0};
            if (uint64_to_str(strThreshold, sizeof(strThreshold), initValidator->threshold) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strThreshold, pageIdx, pageCount);
            break;
        }
        case 3:
            snprintf(outKey, outKeyLen, "Consensus key");
            const bytes_t *consensusKey = &ctx->tx_obj->initValidator.consensus_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), consensusKey->ptr, consensusKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Ethereum cold key");
            const bytes_t *ethColdKey = &ctx->tx_obj->initValidator.eth_cold_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), ethColdKey->ptr, ethColdKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Ethereum hot key");
            const bytes_t *ethHotKey = &ctx->tx_obj->initValidator.eth_hot_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), ethHotKey->ptr, ethHotKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Protocol key");
            const bytes_t *protocolKey = &ctx->tx_obj->initValidator.protocol_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), protocolKey->ptr, protocolKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 7:
            snprintf(outKey, outKeyLen, "DKG key");
            const bytes_t *dkgKey = &ctx->tx_obj->initValidator.dkg_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), dkgKey->ptr, dkgKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 8:
            snprintf(outKey, outKeyLen, "Commission rate");
            CHECK_ERROR(printAmount(&ctx->tx_obj->initValidator.commission_rate, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        case 9:
            snprintf(outKey, outKeyLen, "Maximum commission rate change");
            CHECK_ERROR(printAmount(&ctx->tx_obj->initValidator.max_commission_rate_change, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        case 10:
            snprintf(outKey, outKeyLen, "Validator VP type");
            pageString(outVal, outValLen,ctx->tx_obj->initValidator.vp_type_text, pageIdx, pageCount);
            if (app_mode_expert()) {
                CHECK_ERROR(printVPTypeHash(&ctx->tx_obj->initValidator.vp_type_hash,
                                            outVal, outValLen, pageIdx, pageCount))
            }
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 10 + account_keys_num;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}


static parser_error_t printWithdrawTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {

    // Bump itemIdx if source is not present
    if (ctx->tx_obj->withdraw.has_source == 0 && displayIdx >= 1) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Withdraw");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            if (ctx->tx_obj->withdraw.has_source == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Source");
            CHECK_ERROR(printAddress(ctx->tx_obj->withdraw.source, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->withdraw.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 3;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printCommissionChangeTxn( const parser_context_t *ctx,
                                                uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Change commission");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "New rate");
            CHECK_ERROR(printAmount(&ctx->tx_obj->commissionChange.new_rate, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->commissionChange.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 3;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printIBCTxn( const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    const tx_ibc_t *ibc = &ctx->tx_obj->ibc;
    char buffer[100] = {0};

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "IBC");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Source port");
            pageStringExt(outVal, outValLen, (const char*)ibc->port_id.ptr, ibc->port_id.len, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Source channel");
            pageStringExt(outVal, outValLen, (const char*)ibc->channel_id.ptr, ibc->channel_id.len, pageIdx, pageCount);
            break;
        case 3:
            if( ibc->token_address.len + ibc->token_amount.len > sizeof(buffer)) {
                return parser_unexpected_buffer_end;
            }
            snprintf(outKey, outKeyLen, "Token");
            snprintf(buffer, sizeof(buffer), "%.*s %.*s", ibc->token_amount.len, ibc->token_amount.ptr, ibc->token_address.len, ibc->token_address.ptr);
            pageStringExt(outVal, outValLen, buffer, sizeof(buffer), pageIdx, pageCount);
            break;

        case 4:
            snprintf(outKey, outKeyLen, "Sender");
            pageStringExt(outVal, outValLen, (const char*)ibc->sender_address.ptr, ibc->sender_address.len, pageIdx, pageCount);
            break;

        case 5:
            snprintf(outKey, outKeyLen, "Receiver");
            pageStringExt(outVal, outValLen, (const char*)ibc->receiver.ptr, ibc->receiver.len, pageIdx, pageCount);
            break;

        case 6:
            snprintf(outKey, outKeyLen, "Timeout height");
            if (ibc->timeout_height != 0) {
                return parser_unexpected_value;
            }
            snprintf(outVal, outValLen, "no timeout");
            break;

        case 7: {
            snprintf(outKey, outKeyLen, "Timeout timestamp");
            timedata_t date;
            if (extractTime(ibc->timeout_timestamp.millis, &date) != zxerr_ok) {
                return parser_unexpected_error;
            }
            snprintf(outVal, outValLen, "%04d-%02d-%02dT%02d:%02d:%02d.%09dZ",
            date.tm_year, date.tm_mon, date.tm_day, date.tm_hour, date.tm_min, date.tm_sec, ibc->timeout_timestamp.nanos);
            // printTime(outVal, outValLen, ibc->timeout_timestamp.millis);
            break;
        }


        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 8;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

parser_error_t printTxnFields(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    switch (ctx->tx_obj->typeTx) {
        case Bond:
        case Unbond:
            return printBondTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Custom:
            return printCustomTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Transfer:
            return printTransferTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitAccount:
            return printInitAccountTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitProposal:
            return printInitProposalTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case VoteProposal:
            return printVoteProposalTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case RevealPubkey:
            return printRevealPubkeyTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Withdraw:
            return printWithdrawTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case CommissionChange:
            return printCommissionChangeTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitValidator:
            return printInitValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UpdateVP:
            return printUpdateVPTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UnjailValidator:
            return printUnjailValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case IBC:
            return printIBCTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
