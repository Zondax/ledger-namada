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

#include <stdbool.h>
#include <zxformat.h>
#include "zxerror.h"
#include "timeutils.h"

#include "coin.h"

#include "bech32.h"

// static const char* prefix_implicit = "imp::";
// static const char* prefix_established = "est::";
// static const char* prefix_internal = "int::";

parser_error_t printAddress( bytes_t pubkeyHash,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    char address[110] = {0};
    CHECK_ERROR(readAddress(pubkeyHash, address, sizeof(address)))
    pageString(outVal, outValLen, (const char*) address, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printCodeHash(bytes_t *codeHash,
                             char *outKey, uint16_t outKeyLen,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    char hexString[65] = {0};
    snprintf(outKey, outKeyLen, "Code hash");
    array_to_hexstr((char*) hexString, sizeof(hexString), codeHash->ptr, codeHash->len);
    pageString(outVal, outValLen, (const char*) hexString, pageIdx, pageCount);

    return parser_ok;
}

static parser_error_t printTimestamp(const bytes_t timestamp,
                                     char *outVal, uint16_t outValLen,
                                     uint8_t pageIdx, uint8_t *pageCount) {


    // Received         "2023-04-19T14:19:38.114481351+00:00"
    // Expected         "2023-04-19 14:19:38.114481351 UTC"
    if (timestamp.len != 35) {
        return parser_unexpected_value;
    }

    char date[50] = {0};
    memcpy(date, timestamp.ptr, timestamp.len - 6);
    snprintf(date + 29, sizeof(date) - 29, " UTC");
    if (date[10] == 'T') date[10] = ' ';

    pageString(outVal, outValLen, date, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t printAmount( uint64_t amount, const char* symbol,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount) {

    char strAmount[50] = {0};
    if (uint64_to_str(strAmount, sizeof(strAmount), amount) != NULL ||
        intstr_to_fpstr_inplace(strAmount, sizeof(strAmount), COIN_AMOUNT_DECIMAL_PLACES) == 0) {
        return parser_unexpected_error;
    }

    z_str3join(strAmount, sizeof(strAmount), symbol, "");
    number_inplace_trimming(strAmount, 1);
    pageString(outVal, outValLen, strAmount, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printExpert( const parser_context_t *ctx,
                                   uint8_t displayIdx,
                                   char *outKey, uint16_t outKeyLen,
                                   char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount) {

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Timestamp");
            CHECK_ERROR(printTimestamp(ctx->tx_obj->transaction.timestamp,
                                       outVal, outValLen, pageIdx, pageCount))
            break;
        case 1: {
            const bytes_t *pubkey = &ctx->tx_obj->transaction.header.pubkey;
            char hexString[67] = {0};
            snprintf(outKey, outKeyLen, "Pubkey");
            array_to_hexstr((char*) hexString, sizeof(hexString), pubkey->ptr, pubkey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        }
        case 2:
            snprintf(outKey, outKeyLen, "Epoch");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transaction.header.epoch) != NULL) {
                return parser_unexpected_error;
            }
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Gas limit");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transaction.header.gasLimit) != NULL) {
                return parser_unexpected_error;
            }
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Fees");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transaction.header.fees.amount) != NULL ||
                intstr_to_fpstr_inplace(outVal, outValLen, COIN_AMOUNT_DECIMAL_PLACES) == 0) {
                return parser_unexpected_error;
            }
            z_str3join(outVal, outValLen, COIN_TICKER, "");
            number_inplace_trimming(outVal, 1);
            break;


        default:
            return parser_display_idx_out_of_range;
    }

    return parser_ok;
}
