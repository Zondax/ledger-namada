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

#include "txn_delegation.h"
#include "parser_impl_common.h"
#include "parser_print_common.h"
#include "zxmacros.h"
#include "app_mode.h"
#include "parser_address.h"


parser_error_t readBondUnbond(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/transaction/pos.rs#L24-L35
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    CHECK_ERROR(readAddressAlt(&ctx, &v->bond.validator))

    // Amount
    v->bond.amount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &v->bond.amount.ptr, v->bond.amount.len))

    // Source
    readByte(&ctx, &v->bond.has_source);
    if (v->bond.has_source) {
        CHECK_ERROR(readAddressAlt(&ctx, &v->bond.source))
        v->bond.has_source = 1;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

parser_error_t readRedelegate(const bytes_t *data, tx_redelegation_t *redelegation) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Source validator
    CHECK_ERROR(readAddressAlt(&ctx, &redelegation->src_validator))

    // Destination validator
    CHECK_ERROR(readAddressAlt(&ctx, &redelegation->dest_validator))

    // Owner
    CHECK_ERROR(readAddressAlt(&ctx, &redelegation->owner))

    // Amount
    redelegation->amount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &redelegation->amount.ptr, redelegation->amount.len))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

parser_error_t printRedelegate(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    if (ctx == NULL || outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;

    }
    const bool hasMemo = ctx->tx_obj->transaction.header.memoSection != NULL;
    if (displayIdx >= 5 && !hasMemo) {
        displayIdx++;
    }
    const tx_redelegation_t *redelegation = &ctx->tx_obj->redelegation;
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Redelegate");
            if (app_mode_expert()) {
                CHECK_ERROR(printCodeHash(&ctx->tx_obj->transaction.sections.code, outKey, outKeyLen,
                                          outVal, outValLen, pageIdx, pageCount))
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Source Validator");
            CHECK_ERROR(printAddressAlt(&redelegation->src_validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Destination Validator");
            CHECK_ERROR(printAddressAlt(&redelegation->dest_validator, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Owner");
            CHECK_ERROR(printAddressAlt(&redelegation->owner, outVal, outValLen, pageIdx, pageCount))
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Amount");
            CHECK_ERROR(printAmount(&redelegation->amount, false, COIN_AMOUNT_DECIMAL_PLACES, "",
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
