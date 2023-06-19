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
#include "app_mode.h"
#include <zxmacros.h>
#include <zxformat.h>
#include "coin.h"

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
        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->bond.amount) != NULL ||
                intstr_to_fpstr_inplace(outVal, outValLen, COIN_AMOUNT_DECIMAL_PLACES) == 0) {
                return parser_unexpected_error;
            }
            z_str3join(outVal, outValLen, COIN_TICKER, "");
            number_inplace_trimming(outVal, 1);
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
            if (ctx->tx_obj->bond.has_source == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Sender");
            CHECK_ERROR(printAddress(ctx->tx_obj->transfer.source_address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Destination");
            CHECK_ERROR(printAddress(ctx->tx_obj->transfer.target_address, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(ctx->tx_obj->transfer.amount, ctx->tx_obj->transfer.symbol,
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
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            snprintf(outKey, outKeyLen, "Type");
            CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
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

    char hexString[67] = {0};
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Account");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Public key");
            const bytes_t *pubkey = &ctx->tx_obj->initAccount.pubkey;
            array_to_hexstr((char*) hexString, sizeof(hexString), pubkey->ptr, pubkey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 2:
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
            displayIdx -= 3;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}
#if(0)
static parser_error_t printInitProposalTxn(  const parser_context_t *ctx,
                                              uint8_t displayIdx,
                                              char *outKey, uint16_t outKeyLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    // Bump itemIdx if ID is not present
    if (ctx->tx_obj->initProposal.has_id == 0 && displayIdx >= 1) {
        displayIdx++;
    }
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
            char id[20] = {0};
            memcpy(id, ctx->tx_obj->initProposal.proposal_id.ptr, ctx->tx_obj->initProposal.proposal_id.len);
            pageString(outVal, outValLen, id, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Author");
            CHECK_ERROR(printAddress(ctx->tx_obj->initProposal.author, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Voting start epoch");
            // Less than 20 characters are epochs are uint64
            char strVotingStartEpoch[20] = {0};
            if (uint64_to_str(strVotingStartEpoch, sizeof(strVotingStartEpoch), ctx->tx_obj->initProposal.voting_start_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strVotingStartEpoch, pageIdx, pageCount);
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Voting end epoch");
            // Less than 20 characters are epochs are uint64
            char strVotingEndEpoch[20] = {0};
            if (uint64_to_str(strVotingEndEpoch, sizeof(strVotingEndEpoch), ctx->tx_obj->initProposal.voting_end_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strVotingEndEpoch, pageIdx, pageCount);
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Grace epoch");
            // Less than 20 characters are epochs are uint64
            char strGraceEpoch[20] = {0};
            if (uint64_to_str(strGraceEpoch, sizeof(strGraceEpoch), ctx->tx_obj->initProposal.grace_epoch) != NULL) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strGraceEpoch, pageIdx, pageCount);
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Proposal code");
            char hexString[65] = {0};
            array_to_hexstr((char*) hexString, sizeof(hexString), ctx->tx_obj->initProposal.proposal_code.ptr, ctx->tx_obj->initProposal.proposal_code.len);
            pageString(outVal, outValLen, (const char*) hexString, pageIdx, pageCount);
            break;
        case 7:
            snprintf(outKey, outKeyLen, "Content abstract");
            char strAbstract[600] = {0};
            if (ctx->tx_obj->initProposal.content.abstract.len > 600){
                snprintf(outKey, outKeyLen, "Content abstract (truncated)");
                memcpy(strAbstract, ctx->tx_obj->initProposal.content.abstract.ptr, 600);
            } else{
                memcpy(strAbstract, ctx->tx_obj->initProposal.content.abstract.ptr, ctx->tx_obj->initProposal.content.abstract.len);
            }
            pageString(outVal, outValLen, strAbstract, pageIdx, pageCount);
            break;
        case 8:
            snprintf(outKey, outKeyLen, "Content authors");
            char strAuthors[50] = {0};
            if (ctx->tx_obj->initProposal.content.authors.len>50){
                snprintf(outKey, outKeyLen, "Content authors (truncated)");
                memcpy(strAuthors, ctx->tx_obj->initProposal.content.authors.ptr, 50);
            } else{
                memcpy(strAuthors, ctx->tx_obj->initProposal.content.authors.ptr, ctx->tx_obj->initProposal.content.authors.len);
            }
            pageString(outVal, outValLen, strAuthors, pageIdx, pageCount);
            break;
        case 9:
            snprintf(outKey, outKeyLen, "Content created");
            char strCreated[50] = {0};
            memcpy(strCreated, ctx->tx_obj->initProposal.content.created.ptr, ctx->tx_obj->initProposal.content.created.len);
            pageString(outVal, outValLen, strCreated, pageIdx, pageCount);
            break;
        case 10:
            snprintf(outKey, outKeyLen, "Content details");
            char strDetails[500] = {0};
            if (ctx->tx_obj->initProposal.content.details.len > 500){
                snprintf(outKey, outKeyLen, "Content details (truncated)");
                memcpy(strDetails, ctx->tx_obj->initProposal.content.details.ptr, 500);
            } else{
                memcpy(strDetails, ctx->tx_obj->initProposal.content.details.ptr, ctx->tx_obj->initProposal.content.details.len);
            }
            pageString(outVal, outValLen, strDetails, pageIdx, pageCount);
            break;
        case 11:
            snprintf(outKey, outKeyLen, "Content discussions-to");
            char strDiscussionsTo[60] = {0};
            if (ctx->tx_obj->initProposal.content.discussions_to.len > 60){
                snprintf(outKey, outKeyLen, "Content discussions-to (truncated)");
                memcpy(strDiscussionsTo, ctx->tx_obj->initProposal.content.discussions_to.ptr, 60);
            } else{
                memcpy(strDiscussionsTo, ctx->tx_obj->initProposal.content.discussions_to.ptr, ctx->tx_obj->initProposal.content.discussions_to.len);
            }
            pageString(outVal, outValLen, strDiscussionsTo, pageIdx, pageCount);
            break;
        case 12:
            snprintf(outKey, outKeyLen, "Content license");
            char strLicense[50] = {0};
            if (ctx->tx_obj->initProposal.content.license.len>50){
                snprintf(outKey, outKeyLen, "Content license (truncated)");
                memcpy(strLicense, ctx->tx_obj->initProposal.content.license.ptr, 50);
            } else{
                memcpy(strLicense, ctx->tx_obj->initProposal.content.license.ptr, ctx->tx_obj->initProposal.content.license.len);
            }
            pageString(outVal, outValLen, strLicense, pageIdx, pageCount);
            break;
        case 13:
            snprintf(outKey, outKeyLen, "Content motivation");
            char strMotivation[500] = {0};
            if (ctx->tx_obj->initProposal.content.motivation.len > 500){
                snprintf(outKey, outKeyLen, "Content details (truncated)");
                memcpy(strMotivation, ctx->tx_obj->initProposal.content.motivation.ptr, 500);
            } else{
                memcpy(strMotivation, ctx->tx_obj->initProposal.content.motivation.ptr, ctx->tx_obj->initProposal.content.motivation.len);
            }
            pageString(outVal, outValLen, strMotivation, pageIdx, pageCount);
            break;
        case 14:
            snprintf(outKey, outKeyLen, "Content requires");
            // minimum required votes is u64, can be displayed in 20 chars
            char strRequires[20] = {0};
            memcpy(strRequires, ctx->tx_obj->initProposal.content.require.ptr, ctx->tx_obj->initProposal.content.require.len);
            pageString(outVal, outValLen, strRequires, pageIdx, pageCount);
            break;
        case 15:
            snprintf(outKey, outKeyLen, "Content title");
            char strTitle[50] = {0};
            if (ctx->tx_obj->initProposal.content.title.len>50){
                snprintf(outKey, outKeyLen, "Content title (truncated)");
                memcpy(strTitle, ctx->tx_obj->initProposal.content.title.ptr, 50);
            } else{
                memcpy(strTitle, ctx->tx_obj->initProposal.content.title.ptr, ctx->tx_obj->initProposal.content.title.len);
            }
            pageString(outVal, outValLen, strTitle, pageIdx, pageCount);
            break;
        default:
            if (!app_mode_expert()) {
                return parser_display_idx_out_of_range;
            }
            displayIdx -= 16;
            return printExpert(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}
#endif

static parser_error_t printVoteProposalTxn(  const parser_context_t *ctx,
                                             uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    // Bump itemIdx if ID is not present
    if (ctx->tx_obj->voteProposal.number_of_delegations == 0 && displayIdx >= 4) {
        displayIdx++;
    }

    switch (displayIdx) {
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
            if (uint64_to_str(strId, sizeof(strId), ctx->tx_obj->voteProposal.proposal_id) != NULL ) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, strId, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Vote");
            char strVote[5] = {0};
            switch (ctx->tx_obj->voteProposal.proposal_vote) {
                case Yay:
                    memcpy(strVote, "yay", 4);
                    break;
                case Nay:
                    memcpy(strVote, "nay", 4);
                    break;
                default:
                    return parser_unexpected_value;
            }
            pageString(outVal, outValLen, strVote, pageIdx, pageCount);
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Voter");
            CHECK_ERROR(printAddress(ctx->tx_obj->voteProposal.voter, outVal, outValLen, pageIdx, pageCount))
            break;
        case 4:
            if (ctx->tx_obj->voteProposal.number_of_delegations == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Delegations");
            for (uint32_t i = 0; i < ctx->tx_obj->voteProposal.number_of_delegations; ++i) {
                CHECK_ERROR(printAddress(ctx->tx_obj->voteProposal.delegations, outVal, outValLen, pageIdx, pageCount))
            }
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

    char hexString[67] = {0};
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
            array_to_hexstr((char*) hexString, sizeof(hexString), pubkey->ptr, pubkey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
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
    switch (displayIdx) {
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
            displayIdx -= 3;
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
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Init Validator");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code.bytes, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Account key");
            const bytes_t *accountKey = &ctx->tx_obj->initValidator.account_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), accountKey->ptr, accountKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Consensus key");
            const bytes_t *consensusKey = &ctx->tx_obj->initValidator.consensus_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), consensusKey->ptr, consensusKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Protocol key");
            const bytes_t *protocolKey = &ctx->tx_obj->initValidator.protocol_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), protocolKey->ptr, protocolKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 4:
            snprintf(outKey, outKeyLen, "DKG key");
            const bytes_t *dkgKey = &ctx->tx_obj->initValidator.dkg_key;
            array_to_hexstr((char*) hexString, sizeof(hexString), dkgKey->ptr, dkgKey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        case 5:
            snprintf(outKey, outKeyLen, "Commission rate");
            CHECK_ERROR(printDecimal(ctx->tx_obj->initValidator.commission_rate, outVal, outValLen, pageIdx, pageCount))
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Maximum commission rate change");
            CHECK_ERROR(printDecimal(ctx->tx_obj->initValidator.max_commission_rate_change, outVal, outValLen, pageIdx, pageCount))
            break;
        case 7:
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
            displayIdx -= 8;
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
#if(0)
        case InitProposal:
            return printInitProposalTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
#endif
        case VoteProposal:
            return printVoteProposalTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case RevealPubkey:
            return printRevealPubkeyTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Withdraw:
             return printWithdrawTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitValidator:
             return printInitValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case UpdateVP:
            return printUpdateVPTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
