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
#include "bignum.h"

#define PREFIX "yay with councils:\n"
#define PREFIX_COUNCIL "Council: "
#define PREFIX_SPENDING "spending cap: "


#define CHECK_PTR_BOUNDS(count, dstLen)    \
    if((count + 1) >= dstLen) {             \
        return parser_decimal_too_big;     \
    }

static parser_error_t bigint_to_str(const bytes_t *value, bool isSigned, char *output, uint16_t outputLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (output == NULL || value == NULL || value->ptr == NULL) {
        return parser_unexpected_error;
    }

    // it's up to 256, up to 79 chars in decimal
    if (value->len > 32) {
        return parser_unexpected_value;
    }
    bool isNegative = false;
    uint8_t intAbsVal[32] = {0};
    const uint8_t ptrLen = (uint8_t)value->len;
    // check most significant bit (bit sign), if set ==> negative
    // note that is little endian!
    if (isSigned && value->ptr[ptrLen - 1] & 0x80) {
        isNegative = true;
        // to do absolut value we perform two's complement (flip all bits and add 1)
        uint8_t carry = 1;
        for (uint8_t i = 0; i < ptrLen; i++) {
            intAbsVal[i] = (uint8_t)(~value->ptr[i] + carry);
            if (intAbsVal[i] != 0) {
                carry = 0;
            }
        }
    } else {
        memmove(intAbsVal, value->ptr, ptrLen);
    }
    // it's i128 or i256, up to 79 chars in decimal
    uint8_t bcdOut[40] = {0};
    char bufUi[100] = {0};
    bignumLittleEndian_to_bcd(bcdOut, sizeof(bcdOut), intAbsVal, ptrLen);
    // we leave the first char for negative sign!
    if (!bignumLittleEndian_bcdprint(bufUi + (isNegative ? 1 : 0), sizeof(bufUi) - (isNegative ? 1 : 0), bcdOut, sizeof(bcdOut))) {
        return parser_unexpected_buffer_end;
    }

    if (isNegative) {
        bufUi[0] = '-';
    }
    // up to 79 chars
    const uint16_t numLen = strnlen(bufUi, sizeof(bufUi));
    pageStringExt(output, outputLen, bufUi, numLen, pageIdx, pageCount);
    return parser_ok;
}

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
    if (timestamp.len > 38 || timestamp.len < 25) {
        return parser_unexpected_value;
    }

    char date[55] = {0};
    uint32_t offset = timestamp.len - 6;
    memcpy(date, timestamp.ptr, timestamp.len - 6);
    snprintf(date + offset, sizeof(date) - offset, " UTC");
    // Replace date-time separator with space
    char * const separator = strchr(date, 'T');
    if (separator != NULL) {
      *separator = ' ';
    }

    pageString(outVal, outValLen, date, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t printAmount( const bytes_t *amount, bool isSigned, uint8_t amountDenom, const char* symbol,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount) {


    char strAmount[325] = {0};
    CHECK_ERROR(bigint_to_str(amount, isSigned, strAmount, sizeof(strAmount), 0, pageCount))
    const uint8_t isNegative = strAmount[0] == '-' ? 1 : 0;

    if (insertDecimalPoint(strAmount + isNegative, sizeof(strAmount) - isNegative, amountDenom) != zxerr_ok) {
        return parser_unexpected_error;
    }
//    const char *suffix = (amountDenom == 0) ? ".0" : "";
    z_str3join(strAmount, sizeof(strAmount), symbol, "");
    number_inplace_trimming(strAmount, 1);
    pageString(outVal, outValLen, strAmount, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printPublicKey( const bytes_t *pubkey,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount) {
    char bech32String[85] = {0};
    const zxerr_t err = bech32EncodeFromBytes(bech32String,
                        sizeof(bech32String),
                        "tpknam",
                        (uint8_t*) pubkey->ptr,
                        pubkey->len,
                        1,
                        BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    pageString(outVal, outValLen, (const char*) &bech32String, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t joinStrings(const bytes_t first, const bytes_t second, const char *separator,
                            char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {

    if (first.ptr == NULL || second.ptr == NULL || outVal == NULL || pageCount == NULL ||
        outValLen <= 1) {
        return parser_unexpected_error;
    }

    // Calculate the total length needed including the separator and null terminator
    uint32_t totalLength = first.len + strlen(separator) + second.len + 1; // +1 for null terminator

    // The correct formula ensures we divide the total required length (minus 1 for the null terminator)
    // by the available space (outValLen - 1 for the null terminator in each page), rounding up only when necessary.
    *pageCount = (totalLength - 1) / (outValLen - 1) + ((totalLength - 1) % (outValLen - 1) != 0 ? 1 : 0);

    if (pageIdx >= *pageCount) {
        return parser_unexpected_error; // Page index out of range
    }

    // Calculate the start position for the current page
    uint16_t pageStartPos = pageIdx * (outValLen - 1);
    uint16_t endPos = (pageStartPos + outValLen - 1 < totalLength) ? pageStartPos + outValLen - 1 : totalLength;

    // Initialize outVal
    MEMZERO(outVal, outValLen);

    // Temporary variables to track where we are in the copying process
    uint16_t currentPos = 0; // Current position in the total concatenated string
    uint16_t outValPos = 0;  // Current position in the output buffer

    // Copy from first string
    if (pageStartPos < first.len) {
        uint16_t firstPartLen = (pageStartPos + outValLen - 1 <= first.len) ? outValLen - 1 : first.len - pageStartPos;
        memcpy(outVal, first.ptr + pageStartPos, firstPartLen);
        currentPos += firstPartLen;
        outValPos += firstPartLen;
    }

    // Copy separator if within the current page range
    if (pageStartPos <= first.len && endPos > first.len) {
        uint16_t sepCopyLen = strlen(separator);
        if (pageStartPos + outValPos > first.len) {
            // Adjust separator copy length if part of it falls outside the current page
            uint16_t offset = pageStartPos + outValPos - first.len;
            sepCopyLen = sepCopyLen > offset ? sepCopyLen - offset : 0;
        }
        if (sepCopyLen + outValPos > outValLen - 1) {
            sepCopyLen = outValLen - 1 - outValPos;
        }
        if (sepCopyLen > 0) {
            memcpy(outVal + outValPos, separator, sepCopyLen);
            currentPos += sepCopyLen;
            outValPos += sepCopyLen;
        }
    }

    // Adjust currentPos for copying second string
    if (pageStartPos > first.len + strlen(separator)) {
        currentPos = pageStartPos - first.len - strlen(separator);
    } else {
        currentPos = 0;
    }

    // Copy from second string
    if (endPos > first.len + strlen(separator)) {
        uint16_t secondStartPos = (pageStartPos > first.len + strlen(separator)) ? pageStartPos - (first.len + strlen(separator)) : 0;
        uint16_t secondPartLen = second.len - secondStartPos;
        if (outValPos + secondPartLen > outValLen - 1) {
            secondPartLen = outValLen - 1 - outValPos;
        }
        memcpy(outVal + outValPos, second.ptr + secondStartPos, secondPartLen);
        outValPos += secondPartLen;
    }

    // Ensure null-terminated
    outVal[outValPos] = '\0';

    return parser_ok;
}

parser_error_t printExpert( const parser_context_t *ctx,
                                   uint8_t displayIdx,
                                   char *outKey, uint16_t outKeyLen,
                                   char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount) {

    if(displayIdx >= 5 && ctx->tx_obj->transaction.header.fees.symbol != NULL) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Timestamp");
            CHECK_ERROR(printTimestamp(ctx->tx_obj->transaction.timestamp,
                                       outVal, outValLen, pageIdx, pageCount))
            break;
        case 1: {
            const bytes_t *pubkey = &ctx->tx_obj->transaction.header.pubkey;
            snprintf(outKey, outKeyLen, "Pubkey");
            CHECK_ERROR(printPublicKey(pubkey, outVal, outValLen, pageIdx, pageCount));
            break;
        }
        case 2:
            snprintf(outKey, outKeyLen, "Epoch");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transaction.header.epoch) != NULL) {
                return parser_unexpected_error;
            }
            break;
        case 3: {
            snprintf(outKey, outKeyLen, "Gas limit");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transaction.header.gasLimit) != NULL) {
                return parser_unexpected_error;
            }
            break;
        }
        case 4: {
            if(ctx->tx_obj->transaction.header.fees.symbol != NULL) {
                snprintf(outKey, outKeyLen, "Fees/gas unit");
                CHECK_ERROR(printAmount(&ctx->tx_obj->transaction.header.fees.amount, true, ctx->tx_obj->transaction.header.fees.denom, "", outVal, outValLen, pageIdx, pageCount))
            } else {
                snprintf(outKey, outKeyLen, "Fee token");
                CHECK_ERROR(printAddress(ctx->tx_obj->transaction.header.fees.address, outVal, outValLen, pageIdx, pageCount))
            }
            break;
        }
        case 5: {
            snprintf(outKey, outKeyLen, "Fees/gas unit");
            CHECK_ERROR(printAmount(&ctx->tx_obj->transaction.header.fees.amount, true, ctx->tx_obj->transaction.header.fees.denom, "", outVal, outValLen, pageIdx, pageCount))
            break;
        }
        default:
            return parser_display_idx_out_of_range;
    }

    return parser_ok;
}
