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

#define PREFIX "yay with councils:\n"
#define PREFIX_COUNCIL "Council: "
#define PREFIX_SPENDING "spending cap: "

parser_error_t printAddress( bytes_t pubkeyHash,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    char address[110] = {0};
    CHECK_ERROR(readAddress(pubkeyHash, address, sizeof(address)))
    pageString(outVal, outValLen, (const char*) address, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printCouncilVote(const council_t *council,
                                char *outVal, uint16_t outValLen,
                                uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t offset = 0;
    char strVote[200] = {0};

    // Print prefix
    snprintf(strVote, sizeof(strVote) - offset, PREFIX);
    offset = strlen(strVote);

    // Print council prefix
    char address[110] = {0};
    CHECK_ERROR(readAddress(council->council_address, address, sizeof(address)))
    if (offset + strlen(PREFIX_COUNCIL) + strnlen(address, sizeof(address)) + 2 > sizeof(strVote)) {
        return parser_unexpected_buffer_end;
    }
    snprintf(strVote + offset, sizeof(strVote) - offset, PREFIX_COUNCIL "%s, ", address);
    offset = strlen(strVote);

    // Print spending cap
    char spendingCap[50] = {0};
    if (uint64_to_str(spendingCap, sizeof(spendingCap), council->amount) != NULL ||
        intstr_to_fpstr_inplace(spendingCap, sizeof(spendingCap), COIN_AMOUNT_DECIMAL_PLACES) == 0) {
        return parser_unexpected_error;
    }
    number_inplace_trimming(spendingCap, 1);
    if (offset + strlen(PREFIX_SPENDING) + strnlen(spendingCap, sizeof(spendingCap)) > sizeof(strVote)) {
        return parser_unexpected_buffer_end;
    }
    snprintf(strVote + offset, sizeof(strVote) - offset, PREFIX_SPENDING "%s", spendingCap);

#if 0
    if (number_printed < number_of_councils){
        const char* dots = NULL;
        dots = PIC("...");
        snprintf((char*) strVote + offset, strlen(dots) + 1, "%s", dots);
    }
#endif

    pageString(outVal, outValLen, (const char*) strVote, pageIdx, pageCount);
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

parser_error_t printVPTypeHash(bytes_t *codeHash,
                               char *outVal, uint16_t outValLen,
                               uint8_t pageIdx, uint8_t *pageCount) {

    char hexString[65] = {0};
    array_to_hexstr((char*) hexString, sizeof(hexString), codeHash->ptr, codeHash->len);
    pageString(outVal, outValLen, (const char*) hexString, pageIdx, pageCount);

    return parser_ok;
}

void decimal_to_string(int64_t num, uint32_t scale, char* strDec, size_t bufferSize) {
    if (strDec == NULL || bufferSize == 0) {
        return; // Invalid output buffer
    }

    // Initialize the output buffer
    for (size_t i = 0; i < bufferSize; i++) {
        strDec[i] = '\0';
    }

    // Handle negative value
    if (num < 0) {
        strDec[0] = '-';
        num = -num;
    }

    // Convert the integer part to string
    size_t index = (num < 0) ? 1 : 0;
    int64_t divisor = 1;
    for (uint32_t i = 0; i < scale; i++) {
        divisor *= 10;
    }

    int64_t integerPart = num / divisor;
    int64_t fractionalPart = num % divisor;

    if (integerPart == 0) {
        strDec[index++] = '0';
    } else {
        int64_t tmp_int = integerPart;
        while (tmp_int > 0 && index < bufferSize - 1) {
            strDec[index++] = '0' + (tmp_int % 10);
            tmp_int /= 10;
        }

        // Reverse the integer part
        for (size_t i = (num < 0) ? 1 : 0, j = index - 1; i < j; i++, j--) {
            char tmp_char = strDec[i];
            strDec[i] = strDec[j];
            strDec[j] = tmp_char;
        }
    }

    // Append the decimal point
    if (scale > 0 && index < bufferSize - 1) {
        strDec[index++] = '.';
    }

    // Convert the fractional part to string with leading zeros
    while (scale > 0 && index < bufferSize - 1) {
        divisor /= 10;
        strDec[index++] = '0' + (fractionalPart / divisor);
        fractionalPart %= divisor;
        scale--;
    }
}


// Print a decimal, which is characterised by an uint32_t scale and int64_t num
// for example scale = 2 and num = 1 prints 0.01
parser_error_t printDecimal( const serialized_decimal decimal,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {
    char strDec[100] = {0};
    decimal_to_string(decimal.num, decimal.scale, (char*) strDec, 100);
    number_inplace_trimming(strDec, 1);
    pageString(outVal, outValLen, strDec, pageIdx, pageCount);

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
