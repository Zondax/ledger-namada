/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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
#include "parser_address.h"
#include "bech32_encoding.h"
#include "crypto_helper.h"

#include "txn_delegation.h"

static parser_error_t printBondTxn( const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    // Bump itemIdx if source is not present
    if (ctx->tx_obj->bond.has_source == 0 && displayIdx >= 1) {
        displayIdx++;
    }
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 4 && !hasMemo) {
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
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            if (ctx->tx_obj->bond.has_source == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Source");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->bond.source, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->bond.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(&ctx->tx_obj->bond.amount, false, COIN_AMOUNT_DECIMAL_PLACES, COIN_TICKER,
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        case 4:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 5;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printResignSteward( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 2 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Resign Steward");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Steward");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->resignSteward.steward, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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

static parser_error_t printTransferTxn( const parser_context_t *ctx,
                                        const transaction_type_e type,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {

    if(displayIdx >= 4 && ctx->tx_obj->transfer.symbol) {
        displayIdx++;
    }
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 5 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            if (type == TransparentTransfer) {
              snprintf(outVal, outValLen, "Transparent Transfer");
            } else if (type == ShieldingTransfer) {
              snprintf(outVal, outValLen, "Shielding Transfer");
            } else if (type == ShieldedTransfer) {
              snprintf(outVal, outValLen, "Shielded Transfer");
            } else if (type == UnshieldingTransfer) {
              snprintf(outVal, outValLen, "Unshielding Transfer");
            }
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Sender");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.source_address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Destination");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.target_address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            if(ctx->tx_obj->transfer.symbol != NULL) {
                snprintf(outKey, outKeyLen, "Amount");
                CHECK_ERROR(printAmount(&ctx->tx_obj->transfer.amount, false, ctx->tx_obj->transfer.amount_denom,
                                    ctx->tx_obj->transfer.symbol,
                                    outVal, outValLen, pageIdx, pageCount))
            } else {
                snprintf(outKey, outKeyLen, "Token");
                CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.token, outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(&ctx->tx_obj->transfer.amount, false, ctx->tx_obj->transfer.amount_denom,
                                    "",
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        case 5:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 6;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t getSpendfromIndex(uint32_t index, bytes_t *spend) {

    for (uint32_t i = 0; i < index; i++) {
        spend->ptr += EXTENDED_FVK_LEN + DIVERSIFIER_LEN + NOTE_LEN;
        uint8_t tmp_len = spend->ptr[0];
        spend->ptr++;
        spend->ptr += (tmp_len * (32 + 1)) + sizeof(uint64_t);
    }

    return parser_ok;
}

static parser_error_t getOutputfromIndex(uint32_t index, bytes_t *out) {

    for (uint32_t i = 0; i < index; i++) {
        uint8_t has_ovk = out->ptr[0];
        if(has_ovk) {
            out->ptr += 33;
        } else {
            out->ptr++;
        }
        out->ptr += DIVERSIFIER_LEN + PAYMENT_ADDR_LEN + OUT_NOTE_LEN + MEMO_LEN;
    }

    return parser_ok;
}

uint16_t spend_index = 0;
uint16_t out_index = 0;

static parser_error_t printMaspTransferTxn( const parser_context_t *ctx,
                                        const transaction_type_e type,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    // Compute number of spends/outs in the builder tx , and number of itemns to be printer for each
    uint32_t n_spends = ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.n_spends;
    uint32_t n_outs = ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.n_outputs;
    uint32_t n_send_items = n_spends > 0 ? n_spends * 3 : 3;
    uint32_t n_dest_items = n_outs > 0 ? n_outs * 3 : 3;

    // Its possible for the source or target addres in the transfer body to have a Masp type
    // but the number of spends/outs in the builder tx be 0. this means we will not print the items
    if(displayIdx >= 1 && n_spends == 0 && ctx->tx_obj->transfer.source_address.tag == 2) {
        displayIdx += 3;
    }
    if(displayIdx >= 4 && n_outs == 0 && ctx->tx_obj->transfer.target_address.tag == 2) {
        displayIdx += 3;
    }

    // Reset the index used for jumping outs/spends when we are in the item 0
    if(displayIdx == 0) {
        out_index = 0;
        spend_index = 0;
    }

    // Display Idx will be manipulated, so save the original for further use
    uint8_t orig_idx = displayIdx;

    // Get pointer to the spends
    bytes_t spend = ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.spends;

    // For each spend, we will print 3 items, if we have more then 3 items we need to rebase the display Idx to keep printing the spends
    if(n_send_items > 3 ) {
        if(displayIdx >= 4 && displayIdx <= n_send_items) {
            displayIdx = displayIdx % 3;
            displayIdx = displayIdx == 0 ? 3 : displayIdx;
            if (displayIdx == 1 && pageIdx == 0) {
                // If displayIdx was rebase to first item to be printed, we need to increment the spend index
                spend_index ++;
            }
        } else if(displayIdx > n_send_items) { // If we are done printing the spends, we need to keep rebasing the display idx so we can enter the corrent case
            displayIdx -= (n_send_items - 3);
            spend_index = 0;
        }
        // Get new spend pointer
        getSpendfromIndex(spend_index, &spend);
    }

    // Get pointer to the outputs
    bytes_t out = ctx->tx_obj->transaction.sections.maspBuilder.builder.sapling_builder.outputs;

    // For each output, we will print 3 items, if we have more then 3 items we need to rebase the display Idx to keep printing the outputs
    if(n_dest_items > 3 ) {
        if(displayIdx >= 7 && displayIdx <= n_send_items + n_dest_items && orig_idx <= (n_send_items + n_dest_items)) {
            displayIdx = (displayIdx % 6) + 3;
            if (displayIdx == 4 && pageIdx == 0) {
                // If displayIdx was rebase to first item to be printed, we need to increment the out index
                out_index ++;
            }
        } else if(displayIdx > n_dest_items) {
            displayIdx -= (n_dest_items - 3);
            out_index = 0;
        }
        // Get new output pointer
        getOutputfromIndex(out_index, &out);
    }

    // Check if Memo needs to be printed or not
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 7 && !hasMemo) {
        displayIdx++;
    }

    char tmp_buf[500] = {0};
    uint8_t tmp_amount[32] = {0};
    bytes_t amount_bytes = {tmp_amount, 32};
    const uint8_t *amount = {0};

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            if (type == TransparentTransfer) {
              snprintf(outVal, outValLen, "Transparent Transfer");
            } else if (type == ShieldingTransfer) {
              snprintf(outVal, outValLen, "Shielding Transfer");
            } else if (type == ShieldedTransfer) {
              snprintf(outVal, outValLen, "Shielded Transfer");
            } else if (type == UnshieldingTransfer) {
              snprintf(outVal, outValLen, "Unshielding Transfer");
            }
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Sender");
            if (ctx->tx_obj->transfer.source_address.tag != 2) {
                CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.source_address, outVal, outValLen, pageIdx, pageCount))
            } else {
                CHECK_ERROR(crypto_encodeLargeBech32(spend.ptr, EXTENDED_FVK_LEN, (uint8_t*) tmp_buf, sizeof(tmp_buf), 0));
                pageString(outVal, outValLen, (const char*) tmp_buf, pageIdx, pageCount);
            }

            break;
        case 2:
            snprintf(outKey, outKeyLen, "Sending Token");
            if (ctx->tx_obj->transfer.source_address.tag != 2) {
                CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.token, outVal, outValLen, pageIdx, pageCount))
            } else {     
                const uint8_t *token = spend.ptr + EXTENDED_FVK_LEN + DIVERSIFIER_LEN;
                array_to_hexstr(tmp_buf, sizeof(tmp_buf), token, ASSET_ID_LEN);
                pageString(outVal, outValLen, (const char*) tmp_buf, pageIdx, pageCount);
            }
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Sending Amount");
            if (ctx->tx_obj->transfer.source_address.tag != 2) {
                CHECK_ERROR(printAmount(&ctx->tx_obj->transfer.amount, false, ctx->tx_obj->transfer.amount_denom,
                                        "",
                                        outVal, outValLen, pageIdx, pageCount))
            } else {
                amount = spend.ptr + EXTENDED_FVK_LEN + DIVERSIFIER_LEN + ASSET_ID_LEN;
                // tmp_amount is a 32 bytes array that represents an uint64[4] array, position will determine amount postion inside the array
                MEMCPY(tmp_amount + (ctx->tx_obj->transaction.sections.maspBuilder.asset_data.position * sizeof(uint64_t)), amount, sizeof(uint64_t));
                printAmount(&amount_bytes, false, ctx->tx_obj->transaction.sections.maspBuilder.asset_data.denom, "", outVal, outValLen, pageIdx, pageCount);
            }
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Destination");
            if(ctx->tx_obj->transfer.target_address.tag != 2) {
                CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.target_address, outVal, outValLen, pageIdx, pageCount))
            } else {
                CHECK_ERROR(crypto_encodeLargeBech32(out.ptr + (out.ptr[0] ? 33 : 1), PAYMENT_ADDR_LEN + DIVERSIFIER_LEN, (uint8_t*) tmp_buf, sizeof(tmp_buf), 1));
                pageString(outVal, outValLen, (const char*) tmp_buf, pageIdx, pageCount);
            }
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Receiving Token");
            if (ctx->tx_obj->transfer.target_address.tag != 2) {
                CHECK_ERROR(printAddressAlt(&ctx->tx_obj->transfer.token, outVal, outValLen, pageIdx, pageCount))
            } else {
                const uint8_t *rtoken = out.ptr + (out.ptr[0] ? 33 : 1) + PAYMENT_ADDR_LEN + DIVERSIFIER_LEN;
                array_to_hexstr(tmp_buf, sizeof(tmp_buf), rtoken, ASSET_ID_LEN);
                pageString(outVal, outValLen, (const char*) tmp_buf, pageIdx, pageCount);
            }
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Receiving Amount");
            if (ctx->tx_obj->transfer.target_address.tag != 2) {
                CHECK_ERROR(printAmount(&ctx->tx_obj->transfer.amount, false, ctx->tx_obj->transfer.amount_denom,
                                        "",
                                        outVal, outValLen, pageIdx, pageCount))
            } else {
                amount = out.ptr + (out.ptr[0] ? 33 : 1) + PAYMENT_ADDR_LEN + DIVERSIFIER_LEN + ASSET_ID_LEN;
                MEMCPY(tmp_amount + (ctx->tx_obj->transaction.sections.maspBuilder.asset_data.position * sizeof(uint64_t)), amount, sizeof(uint64_t));
                printAmount(&amount_bytes, false, ctx->tx_obj->transaction.sections.maspBuilder.asset_data.denom, "", outVal, outValLen, pageIdx, pageCount);
            }
            break;
        case 7:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
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
    uint8_t adjustedDisplayIdx = \
        (displayIdx < pubkeys_first_field_idx) \
            ? displayIdx
            : ((displayIdx < pubkeys_first_field_idx + pubkeys_num) \
                ? pubkeys_first_field_idx
                : displayIdx - pubkeys_num + 1);

    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (adjustedDisplayIdx >= 4 && !hasMemo) {
        adjustedDisplayIdx++;
    }

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Account");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            if (pubkeys_num == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Public key");
            const uint8_t keyIndex = 1 + (displayIdx - pubkeys_first_field_idx);
            bytes_t pubkey = {0};
            parser_context_t tmpCtx = {.buffer = ctx->tx_obj->initAccount.pubkeys.ptr, .bufferLen = ctx->tx_obj->initAccount.pubkeys.len, .offset = 0};
            for (uint8_t i = 0; i < keyIndex; i++) {
                CHECK_ERROR(readPubkey(&tmpCtx, &pubkey))
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
                pageStringHex(outVal, outValLen, (const char*)ctx->tx_obj->initAccount.vp_type_hash.ptr, ctx->tx_obj->initAccount.vp_type_hash.len, pageIdx, pageCount);
            }
            break;
        case 4:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 3 + pubkeys_num + (hasMemo ? 1 : 0);
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printInitProposalTxn(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    const tx_init_proposal_t  *initProposal = &ctx->tx_obj->initProposal;
    uint8_t adjustedIdx = displayIdx;

    uint32_t proposalElements = 1;
    switch (initProposal->proposal_type) {
        case Default:
            break;
        case DefaultWithWasm:
            proposalElements += 1;
            break;
        case PGFSteward:
            proposalElements += initProposal->pgf_steward_actions_num;
            break;
        case PGFPayment:
            proposalElements += 3 * initProposal->pgf_payment_actions_num + 2 * initProposal->pgf_payment_ibc_num;
            break;
    }

    if (displayIdx >= 1 && displayIdx < 1 + proposalElements) {
        adjustedIdx = 1;
    }
    if (displayIdx >= 1 + proposalElements) {
        adjustedIdx = displayIdx - proposalElements + 1;
    }
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (adjustedIdx >= 7 && !hasMemo) {
        adjustedIdx++;
    }
    // Less than 20 characters are epochs are uint64
    char strEpoch[25] = {0};
    switch (adjustedIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init proposal");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;

        case 1: {
            CHECK_ERROR(printProposal(&ctx->tx_obj->initProposal, (displayIdx - 1), outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 2:
            snprintf(outKey, outKeyLen, "Author");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->initProposal.author, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Voting start epoch");
            if (uint64_to_str(strEpoch, sizeof(strEpoch), ctx->tx_obj->initProposal.voting_start_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strEpoch, pageIdx, pageCount);
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Voting end epoch");
            if (uint64_to_str(strEpoch, sizeof(strEpoch), ctx->tx_obj->initProposal.voting_end_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strEpoch, pageIdx, pageCount);
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Activation epoch");
            if (uint64_to_str(strEpoch, sizeof(strEpoch), ctx->tx_obj->initProposal.activation_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strEpoch, pageIdx, pageCount);
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Content");
            char strContent[65] = {0};
            const bytes_t *content = &ctx->tx_obj->initProposal.content_hash;
            array_to_hexstr((char*) strContent, sizeof(strContent), content->ptr, content->len);
            pageString(outVal, outValLen, (const char*) &strContent, pageIdx, pageCount);
            break;

        case 7:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            adjustedIdx -= 8;
            return printExpert(ctx, adjustedIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}


static parser_error_t printVoteProposalTxn(  const parser_context_t *ctx,
                                             uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    tx_vote_proposal_t *voteProposal = &ctx->tx_obj->voteProposal;

    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 4 && !hasMemo) {
        displayIdx++;
    }
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Vote Proposal");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "ID");
            // Less than 20 characters as proposal_id is an Option<u64>
            char strId[30] = {0};
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
                    break;
            }
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Voter");
            CHECK_ERROR(printAddressAlt(&voteProposal->voter, outVal, outValLen, pageIdx, pageCount))
            break;
        case 4:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 5;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}


static parser_error_t printRevealPubkeyTxn(  const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {

    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 2 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Reveal Pubkey");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Public key");
            const bytes_t *pubkey = &ctx->tx_obj->revealPubkey.pubkey;
            CHECK_ERROR(printPublicKey(pubkey, outVal, outValLen, pageIdx, pageCount));
            break;
        case 2:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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

static parser_error_t printChangeConsensusKeyTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 3 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Change consensus key");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "New consensus key");
            CHECK_ERROR(printPublicKey(&ctx->tx_obj->consensusKeyChange.consensus_key, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->consensusKeyChange.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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

static parser_error_t printUnjailValidatorTxn(const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 2 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Unjail Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->unjailValidator.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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

static parser_error_t printActivateValidator(const parser_context_t *ctx,
                                            uint8_t displayIdx,
                                            char *outKey, uint16_t outKeyLen,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 2 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Reactivate Validator");
            if (ctx->tx_obj->typeTx == DeactivateValidator) {
                snprintf(outVal, outValLen, "Deactivate Validator");
            }
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->activateValidator.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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
    // Bump adjustedDisplayIdx if vp_code is not present
    if (adjustedDisplayIdx >= 4 && !updateVp->has_vp_code) {
        adjustedDisplayIdx++;
    }
    if (adjustedDisplayIdx >= 5 && ctx->tx_obj->transaction.header.memoSection == NULL) {
        adjustedDisplayIdx++;
    }

    switch (adjustedDisplayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Update Account");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Address");
            CHECK_ERROR(printAddressAlt(&updateVp->address, outVal, outValLen, pageIdx, pageCount))
            break;

        case 2: {
            if (pubkeys_num == 0) {
                // this should never happen by definition of adjustedDisplayIdx
                return parser_unexpected_error;
            }
            snprintf(outKey, outKeyLen, "Public key");
            const uint8_t keyIndex = 1 + (displayIdx - pubkeys_first_field_idx);
            bytes_t pubkey = {0};
            parser_context_t tmpCtx = {.buffer = updateVp->pubkeys.ptr, .bufferLen = updateVp->pubkeys.len, .offset = 0};
            for (uint8_t i = 0; i < keyIndex; i++) {
                CHECK_ERROR(readPubkey(&tmpCtx, &pubkey))
            }
            CHECK_ERROR(printPublicKey(&pubkey, outVal, outValLen, pageIdx, pageCount));
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
            if (ctx->tx_obj->updateVp.vp_type_text != NULL && !app_mode_expert()) {
                pageString(outVal, outValLen,ctx->tx_obj->updateVp.vp_type_text, pageIdx, pageCount);
            } else {
                pageStringHex(outVal, outValLen, (const char*)ctx->tx_obj->updateVp.vp_type_hash.ptr, ctx->tx_obj->updateVp.vp_type_hash.len, pageIdx, pageCount);
            }
            break;

        case 5:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 5 + pubkeys_num - (updateVp->has_threshold ? 0 : 1) - (updateVp->has_vp_code ? 0 : 1)
                    - (ctx->tx_obj->transaction.header.memoSection ? 0 : 1);
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
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

    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 12 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "Address");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->becomeValidator.address, outVal, outValLen, pageIdx, pageCount))
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
            CHECK_ERROR(printAmount(&ctx->tx_obj->becomeValidator.commission_rate, true, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 7: {
            snprintf(outKey, outKeyLen, "Maximum commission rate change");
            CHECK_ERROR(printAmount(&ctx->tx_obj->becomeValidator.max_commission_rate_change, true, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 8: {
            snprintf(outKey, outKeyLen, "Email");
            snprintf(outVal, outValLen, "");
            if (ctx->tx_obj->becomeValidator.email.len > 0) {
                pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->becomeValidator.email.ptr, ctx->tx_obj->becomeValidator.email.len, pageIdx, pageCount);
            }
            break;
        }
        case 9: {
            snprintf(outKey, outKeyLen, "Description");
            // snprintf(outVal, outValLen, "(none)");
            snprintf(outVal, outValLen, "");
            if (ctx->tx_obj->becomeValidator.description.len > 0) {
                pageStringExt(outVal, outValLen, (const char*)ctx->tx_obj->becomeValidator.description.ptr, ctx->tx_obj->becomeValidator.description.len, pageIdx, pageCount);
            }
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
        case 12:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default: {
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 13;
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
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 3 && !hasMemo) {
        displayIdx++;
    }

    const tx_withdraw_t *withdraw = &ctx->tx_obj->withdraw;
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            if (ctx->tx_obj->typeTx == ClaimRewards) {
                snprintf(outVal, outValLen, "Claim Rewards");
            } else {
                snprintf(outVal, outValLen, "Withdraw");
            }
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            if (withdraw->has_source == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Source");
            CHECK_ERROR(printAddressAlt(&withdraw->source, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&withdraw->validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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

static parser_error_t printCommissionChangeTxn( const parser_context_t *ctx,
                                                uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {

    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 3 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Change commission");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "New rate");
            CHECK_ERROR(printAmount(&ctx->tx_obj->commissionChange.new_rate, true, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&ctx->tx_obj->commissionChange.validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
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

static parser_error_t printIBCTxn( const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    const tx_ibc_t *ibc = &ctx->tx_obj->ibc;
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 8 && !hasMemo) {
        displayIdx++;
    }
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "IBC");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
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
            snprintf(outKey, outKeyLen, "Token");
            CHECK_ERROR(joinStrings(ibc->token_amount, ibc->token_address, " ", outVal, outValLen, pageIdx, pageCount))
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
            if (ibc->timeout_height_type == 0x00) {
                snprintf(outVal, outValLen, "no timeout");
            } else {
                char tmpBuffer[45] = {0};
                if (uint64_to_str(tmpBuffer, sizeof(tmpBuffer), ibc->revision_number) != NULL) {
                    return parser_unexpected_error;
                }
                const uint8_t tmpOffset = strnlen(tmpBuffer, sizeof(tmpBuffer));
                tmpBuffer[tmpOffset] = '-';
                if (uint64_to_str(tmpBuffer + tmpOffset + 1, sizeof(tmpBuffer) - tmpOffset - 1, ibc->revision_height) != NULL) {
                    return parser_unexpected_error;
                }
                pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
            }
            break;

        case 7: {
            snprintf(outKey, outKeyLen, "Timeout timestamp");
            timedata_t date;
            if (extractTime(ibc->timeout_timestamp.millis, &date) != zxerr_ok) {
                return parser_unexpected_error;
            }
            char sec_nanos[15] = {0};
            snprintf(sec_nanos, sizeof(sec_nanos), "%02d.%09d", date.tm_sec, ibc->timeout_timestamp.nanos);
            number_inplace_trimming(sec_nanos, 0);
            snprintf(outVal, outValLen, "%04d-%02d-%02dT%02d:%02d:%sZ",
                    date.tm_year, date.tm_mon, date.tm_day, date.tm_hour, date.tm_min, sec_nanos);
            break;
        }

        case 8:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default:
            if (!app_mode_expert()) {
               return parser_display_idx_out_of_range;
            }
            displayIdx -= 9;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t printUpdateStewardCommission( const parser_context_t *ctx,
                                                uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {

    const tx_update_steward_commission_t *updateStewardCommission = &ctx->tx_obj->updateStewardCommission;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Type");
        snprintf(outVal, outValLen, "Update Steward Commission");
        if (app_mode_expert()) {
            CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                        outVal, outValLen, pageIdx, pageCount))
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Steward");
        CHECK_ERROR(printAddressAlt(&ctx->tx_obj->updateStewardCommission.steward, outVal, outValLen, pageIdx, pageCount))
        return parser_ok;
    }

    // Only enter here if commissionLen > 0
    if (displayIdx >= 2 &&  displayIdx < (2 + 2 * updateStewardCommission->commissionLen)) {
        const bool printValidator = displayIdx % 2 == 0;

        AddressAlt address;
        bytes_t amount = {.ptr = NULL, .len = 32};
        parser_context_t tmpCtx = { .buffer = updateStewardCommission->commission.ptr,
                                    .bufferLen = updateStewardCommission->commission.len,
                                    .offset = 0};
        for (uint8_t i = 0; i < displayIdx / 2; i++) {
            CHECK_ERROR(readAddressAlt(&tmpCtx, &address))
            CHECK_ERROR(readBytes(&tmpCtx, &amount.ptr, amount.len))
        }

        if (printValidator) {
            snprintf(outKey, outKeyLen, "Validator");
            CHECK_ERROR(printAddressAlt(&address, outVal, outValLen, pageIdx, pageCount));
        } else {
            snprintf(outKey, outKeyLen, "Commission Rate");
            CHECK_ERROR(printAmount(&amount, true, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
        }
        return parser_ok;
    }

    if (ctx->tx_obj->transaction.header.memoSection != NULL && displayIdx < (2 + 2 * updateStewardCommission->commissionLen) + 1) {
        CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
        return parser_ok;
    }


    if (!app_mode_expert()) {
        return parser_display_idx_out_of_range;
    }
    // displayIdx will be greater than the right part. No underflow
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    const uint8_t adjustedDisplayIdx  = displayIdx - 2 - (2 * updateStewardCommission->commissionLen) - (hasMemo ? 1 : 0);
    return printExpert(ctx, adjustedDisplayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

static parser_error_t printChangeValidatorMetadata(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    const tx_metadata_change_t *metadataChange = &ctx->tx_obj->metadataChange;

    if(displayIdx >= 2 && metadataChange->email.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 3 && metadataChange->description.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 4 && metadataChange->website.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 5 && metadataChange->discord_handle.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 6 && metadataChange->avatar.ptr == NULL) {
        displayIdx++;
    }
    if(displayIdx >= 7 && !metadataChange->has_commission_rate) {
        displayIdx++;
    }

    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 8 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Change metadata");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "Validator");
            printAddressAlt(&metadataChange->validator, outVal, outValLen, pageIdx, pageCount);
            break;
        }
        case 2: {
            snprintf(outKey, outKeyLen, "Email");
            pageStringExt(outVal, outValLen, (const char*)metadataChange->email.ptr, metadataChange->email.len, pageIdx, pageCount);
            break;
        }
        case 3: {
            snprintf(outKey, outKeyLen, "Description");
            pageStringExt(outVal, outValLen, (const char*)metadataChange->description.ptr, metadataChange->description.len, pageIdx, pageCount);
            break;
        }
        case 4: {
            snprintf(outKey, outKeyLen, "Website");
            pageStringExt(outVal, outValLen, (const char*)metadataChange->website.ptr, metadataChange->website.len, pageIdx, pageCount);
            break;
        }
        case 5: {
            snprintf(outKey, outKeyLen, "Discord handle");
            pageStringExt(outVal, outValLen, (const char*)metadataChange->discord_handle.ptr, metadataChange->discord_handle.len, pageIdx, pageCount);
            break;
        }
          case 6: {
            snprintf(outKey, outKeyLen, "Avatar");
            pageStringExt(outVal, outValLen, (const char*)metadataChange->avatar.ptr, metadataChange->avatar.len, pageIdx, pageCount);
            break;
        }
        case 7: {
            snprintf(outKey, outKeyLen, "Commission rate");
            CHECK_ERROR(printAmount(&metadataChange->commission_rate, true, POS_DECIMAL_PRECISION, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 8:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default: {
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 9;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
    }

    return parser_ok;
}

static parser_error_t printBridgePoolTransfer(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    tx_bridge_pool_transfer_t *bridgePoolTransfer = &ctx->tx_obj->bridgePoolTransfer;
    char tmpBuffer[45] = {0};
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 9 && !hasMemo) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Bridge Pool Transfer");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "Transfer Kind");
            if (bridgePoolTransfer->kind == Nut) {
                snprintf(outVal, outValLen, "NUT");
            } else {
                snprintf(outVal, outValLen, "ERC20");
            }
            break;
        }
        case 2: {
            snprintf(outKey, outKeyLen, "Transfer Sender");
            CHECK_ERROR(printAddressAlt(&bridgePoolTransfer->sender, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 3: {
            snprintf(outKey, outKeyLen, "Transfer Recipient");
            tmpBuffer[0] = '0';
            tmpBuffer[1] = 'x';
            array_to_hexstr(tmpBuffer + 2, sizeof(tmpBuffer) - 2, bridgePoolTransfer->recipient.ptr, bridgePoolTransfer->recipient.len);
            pageStringExt(outVal, outValLen, tmpBuffer, sizeof(tmpBuffer), pageIdx, pageCount);
            break;
        }
        case 4: {
            snprintf(outKey, outKeyLen, "Transfer Asset");
            tmpBuffer[0] = '0';
            tmpBuffer[1] = 'x';
            array_to_hexstr(tmpBuffer + 2, sizeof(tmpBuffer) - 2, bridgePoolTransfer->asset.ptr, bridgePoolTransfer->asset.len);
            pageStringExt(outVal, outValLen, tmpBuffer, sizeof(tmpBuffer), pageIdx, pageCount);
            break;
        }
        case 5: {
            snprintf(outKey, outKeyLen, "Transfer Amount");
            CHECK_ERROR(printAmount(&bridgePoolTransfer->amount, false, 0, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
          case 6: {
            snprintf(outKey, outKeyLen, "Gas Payer");
            CHECK_ERROR(printAddressAlt(&bridgePoolTransfer->gasPayer, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 7: {
            snprintf(outKey, outKeyLen, "Gas Token");
            CHECK_ERROR(printAddressAlt(&bridgePoolTransfer->gasToken, outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 8: {
            snprintf(outKey, outKeyLen, "Gas Amount");
            CHECK_ERROR(printAmount(&bridgePoolTransfer->gasAmount, false, 0, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        case 9:
            CHECK_ERROR(printMemo(ctx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount))
            break;

        default: {
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 10;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
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

        case TransparentTransfer: case ShieldingTransfer: case ShieldedTransfer: case UnshieldingTransfer:
            if(ctx->tx_obj->transaction.isMasp) {
                return printMaspTransferTxn(ctx, ctx->tx_obj->typeTx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
            }
            return printTransferTxn(ctx, ctx->tx_obj->typeTx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitAccount:
             return printInitAccountTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitProposal:
            return printInitProposalTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case VoteProposal:
            return printVoteProposalTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case RevealPubkey:
            return printRevealPubkeyTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ClaimRewards:
        case Withdraw:
             return printWithdrawTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case CommissionChange:
            return printCommissionChangeTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case BecomeValidator:
             return printBecomeValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UpdateVP:
            return printUpdateVPTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UnjailValidator:
            return printUnjailValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ReactivateValidator:
        case DeactivateValidator:
            return printActivateValidator(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case IBC:
            return printIBCTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Redelegate:
            return printRedelegate(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ResignSteward:
            return printResignSteward(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ChangeConsensusKey:
            return printChangeConsensusKeyTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UpdateStewardCommission:
            return printUpdateStewardCommission(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case ChangeValidatorMetadata:
            return printChangeValidatorMetadata(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case BridgePoolTransfer:
            return printBridgePoolTransfer(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
