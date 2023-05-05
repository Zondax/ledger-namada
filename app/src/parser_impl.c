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
#include "parser_impl.h"
#include "zxformat.h"
#include "leb128.h"
#include "app_mode.h"

#include "parser_impl_common.h"

parser_error_t _read(parser_context_t *ctx, parser_tx_t *v) {
    CHECK_ERROR(readTimestamp(ctx, &v->transaction.timestamp))
    CHECK_ERROR(readHeader(ctx, v))
    CHECK_ERROR(readSections(ctx, v))

    CHECK_ERROR(validateTransactionParams(v))

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

        case Transfer:
            *numItems = (app_mode_expert() ? TRANSFER_EXPERT_PARAMS : TRANSFER_NORMAL_PARAMS);
            break;

        case InitAccount:
            *numItems = (app_mode_expert() ? INIT_ACCOUNT_EXPERT_PARAMS : INIT_ACCOUNT_NORMAL_PARAMS);
            break;

        case Withdraw:
            *numItems = (app_mode_expert() ? WITHDRAW_EXPERT_PARAMS : WITHDRAW_NORMAL_PARAMS) + ctx->tx_obj->withdraw.has_source;
            break;

        case InitValidator:
            *numItems = (app_mode_expert() ? INIT_VALIDATOR_EXPERT_PARAMS : INIT_VALIDATOR_NORMAL_PARAMS);
            break;

        default:
            break;
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

        default:
            return "Unrecognized error code";
    }
}
