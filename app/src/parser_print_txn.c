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

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
            CHECK_ERROR(print_uint256(&ctx->tx_obj->bond.amount, COIN_AMOUNT_DECIMAL_PLACES, COIN_TICKER,
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        } default:
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
    if(displayIdx >= 4 && ctx->tx_obj->transfer.symbol) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Transfer");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
            if(ctx->tx_obj->transfer.symbol != NULL) {
                snprintf(outKey, outKeyLen, "Amount");
                CHECK_ERROR(print_uint256(&ctx->tx_obj->transfer.amount, ctx->tx_obj->transfer.amount_denom,
                                    ctx->tx_obj->transfer.symbol,
                                    outVal, outValLen, pageIdx, pageCount))
            } else {
                snprintf(outKey, outKeyLen, "Token");
                CHECK_ERROR(printAddress(ctx->tx_obj->transfer.token, outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(print_uint256(&ctx->tx_obj->transfer.amount, ctx->tx_obj->transfer.amount_denom,
                                    "",
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 5;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printRedelegateTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Redelegate");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Source Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->redelegation.src_validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Destination Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->redelegation.dest_validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Owner");
            CHECK_ERROR(printAddress(ctx->tx_obj->redelegation.owner, outVal, outValLen, pageIdx, pageCount))
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(print_uint256(&ctx->tx_obj->redelegation.amount, COIN_AMOUNT_DECIMAL_PLACES,
                                    "",
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 5;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printReactivateValidatorTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Reactivate Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->reactivateValidator.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 2;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printDeactivateValidatorTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Deactivate Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->reactivateValidator.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 2;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printResignStewardTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Resign Steward");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Steward");
            CHECK_ERROR(printAddress(ctx->tx_obj->resignSteward.steward, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 2;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printChangeConsensusKeyTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Change consensus key");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "New consensus key");
            CHECK_ERROR(printPublicKey(&ctx->tx_obj->consensusKeyChange.consensus_key, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->consensusKeyChange.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 3;
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        default:
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
            bytes_t pubkey;
            bytes_t pub_keys = ctx->tx_obj->initAccount.pubkeys;
            for (uint32_t i = 0; i <= keyIndex; i++) {
              popPublicKey(&pub_keys, &pubkey);
            }
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
            if (ctx->tx_obj->initAccount.vp_type_text != NULL && !app_mode_expert()) {
                pageString(outVal, outValLen,ctx->tx_obj->initAccount.vp_type_text, pageIdx, pageCount);
            } else {
              pageStringHex(outVal, outValLen, (const char*)ctx->tx_obj->initAccount.vp_type_hash, CX_SHA256_SIZE, pageIdx, pageCount);
            }
            break;
        default:
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
                        const uint8_t *codeHash = ctx->tx_obj->initProposal.proposal_code_hash;
                        pageStringHex(outVal, outValLen, (const char*)codeHash, CX_SHA256_SIZE, pageIdx, pageCount);
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
            const uint8_t *content = ctx->tx_obj->initProposal.content_hash;
            array_to_hexstr((char*) strContent, sizeof(strContent), content, CX_SHA256_SIZE);
            pageString(outVal, outValLen, (const char*) &strContent, pageIdx, pageCount);
            break;
        default:
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "ID");
            // Less than 20 characters as proposal_id is an Option<u64>
            char strId[21] = {0};
            if (uint64_to_str(strId, sizeof(strId), voteProposal->proposal_id) != NULL ) {
              return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strId, pageIdx, pageCount);
            break;
        case 2:
          snprintf(outKey, outKeyLen, "Vote");
          switch (voteProposal->proposal_vote) {
          case Yay:
            snprintf(outVal, outValLen, "yay");
            break;
          case Nay:
            snprintf(outVal, outValLen, "nay");
            break;
          case Abstain:
            snprintf(outVal, outValLen, "abstain");
            break;
          default:
            return parser_unexpected_value;
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
            uint8_t delegate_idx = displayIdx - delegations_first_field_idx;
            bytes_t delegations = voteProposal->delegations;
            bytes_t delegation;
            for (uint32_t i = 0; i < delegate_idx+1; ++i) {
              popAddress(&delegations, &delegation);
            }
            CHECK_ERROR(printAddress(delegation, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Public key");
            const bytes_t *pubkey = &ctx->tx_obj->revealPubkey.pubkey;
            CHECK_ERROR(printPublicKey(pubkey, outVal, outValLen, pageIdx, pageCount));
            break;

        default:
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->unjailValidator.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
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
    if (adjustedDisplayIdx >= 4 && !updateVp->has_vp_code) {
        adjustedDisplayIdx++;
    }

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Update Account");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
                bytes_t pub_keys = updateVp->pubkeys;
                bytes_t key;
                for (uint32_t i = 0; i <= key_index; i++) {
                  popPublicKey(&pub_keys, &key);
                }
                CHECK_ERROR(printPublicKey(&key, outVal, outValLen, pageIdx, pageCount));
            } else {
                return parser_unexpected_error;
            }
            break;
        }
        case 3: {
            if (!updateVp->has_threshold) {
                return parser_unexpected_error;
            }
            *pageCount = 1;
            snprintf(outKey, outKeyLen, "Threshold");
            snprintf(outVal, outValLen, "%d", updateVp->threshold);
            break;
        }
        case 4:
            snprintf(outKey, outKeyLen, "VP type");
            if (app_mode_expert() || ctx->tx_obj->updateVp.vp_type_text == NULL) {
              pageStringHex(outVal, outValLen, (const char *) updateVp->vp_type_hash, CX_SHA256_SIZE, pageIdx, pageCount);
            } else {
              pageString(outVal, outValLen,ctx->tx_obj->updateVp.vp_type_text, pageIdx, pageCount);
            }
            break;
        default:
            return printExpert(ctx, adjustedDisplayIdx - 5, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printBecomeValidatorTxn(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    if(displayIdx >= 9 && ctx->tx_obj->becomeValidator.description.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 10 && ctx->tx_obj->becomeValidator.website.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 11 && ctx->tx_obj->becomeValidator.discord_handle.ptr == NULL) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "Address");
            CHECK_ERROR(printAddress(ctx->tx_obj->becomeValidator.address, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 2: {
            snprintf(outKey, outKeyLen, "Consensus key");
            const bytes_t *consensusKey = &ctx->tx_obj->becomeValidator.consensus_key;
            CHECK_ERROR(printPublicKey(consensusKey, outVal, outValLen, pageIdx, pageCount));
            break;
        }
        case 3: {
            snprintf(outKey, outKeyLen, "Ethereum cold key");
            const bytes_t *ethColdKey = &ctx->tx_obj->becomeValidator.eth_cold_key;
            pageStringHex(outVal, outValLen, (const char*) ethColdKey->ptr, ethColdKey->len, pageIdx, pageCount);
            break;
        }
        case 4: {
            snprintf(outKey, outKeyLen, "Ethereum hot key");
            const bytes_t *ethHotKey = &ctx->tx_obj->becomeValidator.eth_hot_key;
            pageStringHex(outVal, outValLen, (const char*) ethHotKey->ptr, ethHotKey->len, pageIdx, pageCount);
            break;
        }
        case 5: {
            snprintf(outKey, outKeyLen, "Protocol key");
            const bytes_t *protocolKey = &ctx->tx_obj->becomeValidator.protocol_key;
            CHECK_ERROR(printPublicKey(protocolKey, outVal, outValLen, pageIdx, pageCount));
            break;
        }
        case 6: {
            snprintf(outKey, outKeyLen, "Commission rate");
            CHECK_ERROR(print_int256(&ctx->tx_obj->becomeValidator.commission_rate, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 7: {
            snprintf(outKey, outKeyLen, "Maximum commission rate change");
            CHECK_ERROR(print_int256(&ctx->tx_obj->becomeValidator.max_commission_rate_change, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 8: {
            snprintf(outKey, outKeyLen, "Email");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->becomeValidator.email.ptr, ctx->tx_obj->becomeValidator.email.len, pageIdx, pageCount);
            break;
        }
        case 9: {
            snprintf(outKey, outKeyLen, "Description");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->becomeValidator.description.ptr, ctx->tx_obj->becomeValidator.description.len, pageIdx, pageCount);
            break;
        }
        case 10: {
            snprintf(outKey, outKeyLen, "Website");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->becomeValidator.website.ptr, ctx->tx_obj->becomeValidator.website.len, pageIdx, pageCount);
            break;
        }
        case 11: {
            snprintf(outKey, outKeyLen, "Discord handle");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->becomeValidator.discord_handle.ptr, ctx->tx_obj->becomeValidator.discord_handle.len, pageIdx, pageCount);
            break;
        }
        default: {
            displayIdx -= 12;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
    }

    return parser_ok;
}

static parser_error_t printChangeValidatorMetadataTxn(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {
    if(displayIdx >= 2 && ctx->tx_obj->metadataChange.email.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 3 && ctx->tx_obj->metadataChange.description.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 4 && ctx->tx_obj->metadataChange.website.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 5 && ctx->tx_obj->metadataChange.discord_handle.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 6 && ctx->tx_obj->metadataChange.avatar.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 7 && !ctx->tx_obj->metadataChange.has_commission_rate) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Change metadata");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "Validator");
            printAddress(ctx->tx_obj->metadataChange.validator, outVal, outValLen, pageIdx, pageCount);
            break;
        }
        case 2: {
            snprintf(outKey, outKeyLen, "Email");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->metadataChange.email.ptr, ctx->tx_obj->metadataChange.email.len, pageIdx, pageCount);
            break;
        }
        case 3: {
            snprintf(outKey, outKeyLen, "Description");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->metadataChange.description.ptr, ctx->tx_obj->metadataChange.description.len, pageIdx, pageCount);
            break;
        }
        case 4: {
            snprintf(outKey, outKeyLen, "Website");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->metadataChange.website.ptr, ctx->tx_obj->metadataChange.website.len, pageIdx, pageCount);
            break;
        }
        case 5: {
            snprintf(outKey, outKeyLen, "Discord handle");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->metadataChange.discord_handle.ptr, ctx->tx_obj->metadataChange.discord_handle.len, pageIdx, pageCount);
            break;
        }
          case 6: {
            snprintf(outKey, outKeyLen, "Avatar");
            pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->metadataChange.avatar.ptr, ctx->tx_obj->metadataChange.avatar.len, pageIdx, pageCount);
            break;
        }
        case 7: {
            snprintf(outKey, outKeyLen, "Commission rate");
            CHECK_ERROR(print_int256(&ctx->tx_obj->metadataChange.commission_rate, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        default: {
            displayIdx -= 8;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
            displayIdx -= 3;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printClaimRewardsTxn( const parser_context_t *ctx,
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
            snprintf(outVal, outValLen, "Claim Rewards");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "New rate");
            CHECK_ERROR(print_int256(&ctx->tx_obj->commissionChange.new_rate, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddress(ctx->tx_obj->commissionChange.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        default:
            displayIdx -= 3;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printUpdateStewardCommissionTxn( const parser_context_t *ctx,
                                                uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {

  uint8_t adjustedDisplayIdx = displayIdx;
  uint8_t commissionIdx = (adjustedDisplayIdx - 2) / 2;
  uint8_t commissionPart = (adjustedDisplayIdx - 2) % 2;
  if (2 <= adjustedDisplayIdx) {
    adjustedDisplayIdx -= MIN(2*commissionIdx + commissionPart + 1, ctx->tx_obj->updateStewardCommission.commissionLen*2);
    adjustedDisplayIdx += 1;
  }
    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Update Steward Commission");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Steward");
            CHECK_ERROR(printAddress(ctx->tx_obj->updateStewardCommission.steward, outVal, outValLen, pageIdx, pageCount))
            break;
    case 2: {
      parser_context_t inner_ctx = {
        .buffer = ctx->tx_obj->updateStewardCommission.commission.ptr,
        .bufferLen = ctx->tx_obj->updateStewardCommission.commission.len,
        .offset = 0,
        .tx_obj = NULL,
      };
      bytes_t address;
      int256_t dec;
      for (uint8_t i = 0; i <= commissionIdx; i++) {
        CHECK_ERROR(readAddressBytes(&inner_ctx, &address))
        CHECK_ERROR(readInt256(&inner_ctx, &dec))
      }
      if (commissionPart == 0) {
        snprintf(outKey, outKeyLen, "Validator");
        CHECK_ERROR(printAddress(address, outVal, outValLen, pageIdx, pageCount))
          } else if (commissionPart == 1) {
        snprintf(outKey, outKeyLen, "Commission Rate");
        CHECK_ERROR(print_int256(&dec, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
          }
      break;
    } default:
            adjustedDisplayIdx -= 3;
            return printExpert(ctx, adjustedDisplayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
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
                CHECK_ERROR(printCodeHash(ctx->tx_obj->transaction.sections.code.bytes_hash, outKey, outKeyLen,
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
            const uint16_t bufferLen = strnlen(buffer, sizeof(buffer));
            pageStringExt(outVal, outValLen, buffer, bufferLen, pageIdx, pageCount);
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

        case ClaimRewards:
             return printClaimRewardsTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case CommissionChange:
            return printCommissionChangeTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case BecomeValidator:
             return printBecomeValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ReactivateValidator:
            return printReactivateValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case DeactivateValidator:
            return printDeactivateValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        
        case UpdateVP:
            return printUpdateVPTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UnjailValidator:
            return printUnjailValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Redelegate:
            return printRedelegateTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case IBC:
            return printIBCTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ChangeValidatorMetadata:
            return printChangeValidatorMetadataTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ChangeConsensusKey:
            return printChangeConsensusKeyTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ResignSteward:
            return printResignStewardTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UpdateStewardCommission:
            return printUpdateStewardCommissionTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
