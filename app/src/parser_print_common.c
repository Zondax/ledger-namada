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

parser_error_t printCouncilVote( uint32_t number_of_councils, council_t *councils,
                                 char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
    uint32_t number_printed = (number_of_councils < MAX_COUNCILS) ?
            number_of_councils : MAX_COUNCILS;
    uint8_t offset = 0;
    char strVote[200] = {0};

    for (uint32_t i = 0; i < number_printed; ++i) {
        MEMZERO(strVote, sizeof (strVote));
        council_t council = councils[i];

        const char* prefix = NULL;
        prefix = PIC("yay with councils:\n");
        snprintf((char*) strVote, strlen(prefix) + 1, "%s", prefix);
        offset += strlen(prefix);

        const char* prefix_council = NULL;
        prefix_council = PIC("Council: ");
        snprintf((char*) strVote + offset, strlen(prefix_council) + 1, "%s", prefix_council);
        offset+= strlen(prefix_council);

        char address[110] = {0};
        CHECK_ERROR(readAddress(council.council_address, address, sizeof(address)))
        snprintf((char*) strVote + offset, strlen(address) + 1, "%s", address);
        offset += strlen(address);

        const char* prefix_spending_cap = NULL;
        prefix_spending_cap = PIC(", spending cap: ");
        snprintf((char*) strVote + offset, strlen(prefix_spending_cap) + 1, "%s", prefix_spending_cap);
        offset += strlen(prefix_spending_cap);

        char strSpendingCap[50] = {0};
        if (uint64_to_str(strSpendingCap, sizeof(strSpendingCap), council.amount) != NULL ||
            intstr_to_fpstr_inplace(strSpendingCap, sizeof(strSpendingCap), COIN_AMOUNT_DECIMAL_PLACES) == 0) {
            return parser_unexpected_error;
        }
        number_inplace_trimming(strSpendingCap, 1);
        snprintf((char*) strVote + offset, strlen(strSpendingCap) + 1, "%s", strSpendingCap);
        offset += strlen(strSpendingCap);
    }

    if (number_printed < number_of_councils){
        const char* dots = NULL;
        dots = PIC("...");
        snprintf((char*) strVote + offset, strlen(dots) + 1, "%s", dots);
    }

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
