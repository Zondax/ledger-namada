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
#include "bech32.h"

static parser_error_t printBondTxn( const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    // Bump itemIdx if source is not present
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
        case 3: {
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(&ctx->tx_obj->bond.amount, COIN_AMOUNT_DECIMAL_PLACES, COIN_TICKER,
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        } default:
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
            if (pubkeys_num == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Public key");
            const uint8_t keyIndex = displayIdx - pubkeys_first_field_idx;
            const bytes_t pubkey = {
              .ptr = ctx->tx_obj->initAccount.pubkeys.ptr + PK_LEN_25519_PLUS_TAG * keyIndex,
              .len = PK_LEN_25519_PLUS_TAG,
            };
            CHECK_ERROR(printPublicKey(&pubkey, outVal, outValLen, pageIdx, pageCount));
            break;
        case 2: {
            snprintf(outKey, outKeyLen, "Threshold");
            // Threshold value is less than 3 characters (uint8)
            char strThreshold[4] = {0};
            if (uint64_to_str(strThreshold, sizeof(strThreshold), initAccount->threshold) != NULL) {
                return parser_unexpected_error;
            }
            snprintf(outVal, outValLen, "%s", strThreshold);
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
            char idString[21] = {0};
            if (uint64_to_str(idString, sizeof(idString), ctx->tx_obj->initProposal.proposal_id) != NULL) {
                return parser_unexpected_error;
            }
            snprintf(outVal, outValLen, "%s", idString);
            break;

        case 2: {
            snprintf(outKey, outKeyLen, "Proposal type");
            switch (ctx->tx_obj->initProposal.proposal_type) {
                case Default:
                    if (ctx->tx_obj->initProposal.has_proposal_code) {
                        const bytes_t *codeHash = &ctx->tx_obj->initProposal.proposal_code_hash;
                        pageStringHex(outVal, outValLen, (const char*)codeHash->ptr, codeHash->len, pageIdx, pageCount);
                    } else {
                        snprintf(outVal, outValLen, "Default");
                    }
                    break;

                case PGFSteward:
                    snprintf(outVal, outValLen, "PGF Steward");
                    break;

                case PGFPayment:
                    snprintf(outVal, outValLen, "PGF Payment");
                    break;

                default:
                    return parser_unexpected_type;
            }
            break;
        }


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


static parser_error_t printVoteProposalTxn(  const parser_context_t *ctx,
                                             uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    tx_vote_proposal_t *voteProposal = &ctx->tx_obj->voteProposal;

    const uint32_t delegations_num = voteProposal->number_of_delegations;
    const uint8_t delegations_first_field_idx = 4;
    const uint8_t adjustedDisplayIdx = \
        (displayIdx < delegations_first_field_idx) \
            ? displayIdx
            : ((displayIdx < delegations_first_field_idx + delegations_num) \
                ? delegations_first_field_idx
                : displayIdx - delegations_num + 1);
    *pageCount = 1;
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
        case 4:
            if (voteProposal->number_of_delegations == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Delegation");
            for (uint32_t i = 0; i < voteProposal->number_of_delegations; ++i) {
                CHECK_ERROR(printAddress(voteProposal->delegations, outVal, outValLen, pageIdx, pageCount))
            }
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= (4 + voteProposal->number_of_delegations);
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}


static parser_error_t printRevealPubkeyTxn(  const parser_context_t *ctx,
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
            const bytes_t *pubkey = &ctx->tx_obj->revealPubkey.pubkey;
            CHECK_ERROR(printPublicKey(pubkey, outVal, outValLen, pageIdx, pageCount));
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
                                       uint8_t pageIdx, uint8_t *pageCount){

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
            CHECK_ERROR(printAddress(updateVp->address, outVal, outValLen, pageIdx, pageCount))
            break;

        case 2: {
            if (pubkeys_num != 0) {
                snprintf(outKey, outKeyLen, "Public key");
                const uint8_t key_index = displayIdx - pubkeys_first_field_idx;
                const bytes_t key = {
                    .ptr = updateVp->pubkeys.ptr + PK_LEN_25519_PLUS_TAG * key_index,
                    .len = PK_LEN_25519_PLUS_TAG,
                };
                CHECK_ERROR(printPublicKey(&key, outVal, outValLen, pageIdx, pageCount));
            } else {
                return parser_unexpected_error;
            }
            break;
        }
        case 3: {
            if (updateVp->has_threshold) {
                snprintf(outKey, outKeyLen, "Threshold");
                // Threshold value is less than 3 characters (uint8)
                char strThreshold[3] = {0};
                if (uint64_to_str(strThreshold, sizeof(strThreshold), updateVp->threshold) != NULL) {
                    return parser_unexpected_error;
                }
                pageString(outVal, outValLen, strThreshold, pageIdx, pageCount);
            } else {
                return parser_unexpected_error;
            }
            break;
        }
        case 4:
            snprintf(outKey, outKeyLen, "VP type");
            if (app_mode_expert()) {
                pageStringHex(outVal, outValLen, (const char*) updateVp->vp_type_hash.ptr, updateVp->vp_type_hash.len, pageIdx, pageCount);
            } else {
                pageString(outVal, outValLen,ctx->tx_obj->updateVp.vp_type_text, pageIdx, pageCount);
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

    const tx_init_validator_t *initValidator = &ctx->tx_obj->initValidator;
    const uint32_t account_keys = initValidator->number_of_account_keys;

    const uint8_t adjustedDisplayIdx = (displayIdx == 0) ? displayIdx : \
    (displayIdx < account_keys + 1) ? 1 : displayIdx - account_keys + 1;

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "Account key");
            const uint8_t key_index = displayIdx - 1;
            const bytes_t key = {
                .ptr = initValidator->account_keys.ptr + PK_LEN_25519_PLUS_TAG * key_index,
                .len = PK_LEN_25519_PLUS_TAG
            };
            CHECK_ERROR(printPublicKey(&key, outVal, outValLen, pageIdx, pageCount));
            break;
        } case 2: {
            snprintf(outKey, outKeyLen, "Threshold");
            // Threshold value is less than 3 characters (uint8)
            char strThreshold[4] = {0};
            if (uint64_to_str(strThreshold, sizeof(strThreshold), initValidator->threshold) != NULL) {
                return parser_unexpected_error;
            }
            snprintf(outVal, outKeyLen, "%s", strThreshold);
            break;
        }
        case 3: {
            snprintf(outKey, outKeyLen, "Consensus key");
            const bytes_t *consensusKey = &ctx->tx_obj->initValidator.consensus_key;
            CHECK_ERROR(printPublicKey(consensusKey, outVal, outValLen, pageIdx, pageCount));
            break;

        } case 4:
            snprintf(outKey, outKeyLen, "Ethereum cold key");
            const bytes_t *ethColdKey = &ctx->tx_obj->initValidator.eth_cold_key;
            pageStringHex(outVal, outValLen, (const char*) ethColdKey->ptr, ethColdKey->len, pageIdx, pageCount);
            break;

        case 5:
            snprintf(outKey, outKeyLen, "Ethereum hot key");
            const bytes_t *ethHotKey = &ctx->tx_obj->initValidator.eth_hot_key;
            pageStringHex(outVal, outValLen, (const char*) ethHotKey->ptr, ethHotKey->len, pageIdx, pageCount);
            break;

        case 6: {
            snprintf(outKey, outKeyLen, "Protocol key");
            const bytes_t *protocolKey = &ctx->tx_obj->initValidator.protocol_key;
            CHECK_ERROR(printPublicKey(protocolKey, outVal, outValLen, pageIdx, pageCount));
            break;
        } case 7: {
            snprintf(outKey, outKeyLen, "DKG key");
            const bytes_t *dkgKey = &ctx->tx_obj->initValidator.dkg_key;
            char bech32String[300] = {0};
            const zxerr_t err = bech32EncodeFromBytes(bech32String,
                                sizeof(bech32String),
                                "dpknam",
                                (uint8_t*) dkgKey->ptr,
                                dkgKey->len,
                                0,
                                BECH32_ENCODING_BECH32M);
            if (err != zxerr_ok) {
              return parser_unexpected_error;
            }
            pageString(outVal, outValLen, (const char*)&bech32String, pageIdx, pageCount);
            break;
        } case 8:
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
            displayIdx -= 10 + account_keys;
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
            int bufferLen = snprintf(buffer, sizeof(buffer), "%.*s %.*s", ibc->token_amount.len, ibc->token_amount.ptr, ibc->token_address.len, ibc->token_address.ptr);
            pageStringExt(outVal, outValLen, buffer, bufferLen+1, pageIdx, pageCount);
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
