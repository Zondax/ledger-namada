/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

#include <stdio.h>
#include <zxmacros.h>
#include <zxformat.h>
#include <zxtypes.h>

#include "coin.h"
#include "parser_common.h"
#include "parser_impl.h"
#include "parser.h"

#include "crypto.h"
#include "crypto_helper.h"
#include "app_mode.h"

#include "timeutils.h"
#include "bech32.h"

#define EXPERT_MODE_NUMITEMS    5

static const char* prefix_implicit = "imp::";
static const char* prefix_established = "est::";
static const char* prefix_internal = "int::";

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL || ctx->tx_obj == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    // MEMZERO(&ctx->tx_obj->outerTxn, sizeof(ctx->tx_obj->outerTxn));
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx,
                            const uint8_t *data,
                            size_t dataLen,
                            parser_tx_t *tx_obj) {
    ctx->tx_obj = tx_obj;
    CHECK_ERROR(parser_init_context(ctx, data, dataLen))
    return _read(ctx, tx_obj);
}

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    return getNumItems(ctx, num_items);
}

static void cleanOutput(char *outKey, uint16_t outKeyLen,
                        char *outVal, uint16_t outValLen)
{
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx)
{
    if ( displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

static parser_error_t printAddress( bytes_t pubkeyHash,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    const uint8_t addressType = *pubkeyHash.ptr++;
    const char* prefix = NULL;

    switch (addressType) {
        case 0:
            prefix = PIC(prefix_established);
            break;
        case 1:
            prefix = PIC(prefix_implicit);
            break;
        case 2:
            prefix = PIC(prefix_internal);
            break;

        default:
            return parser_value_out_of_range;
    }

    uint32_t hashLen = 0;
    MEMCPY(&hashLen, pubkeyHash.ptr, sizeof(uint32_t));
    pubkeyHash.ptr += sizeof(uint32_t);
    if (hashLen != PK_HASH_LEN) {
        return parser_unexpected_value;
    }

    uint8_t tmpBuffer[FIXED_LEN_STRING_BYTES] = {0};
    snprintf((char*) tmpBuffer, sizeof(tmpBuffer), "%s", prefix);
    MEMCPY(tmpBuffer + strnlen(prefix, 5), pubkeyHash.ptr, PK_HASH_LEN);

    const char *hrp = true ? "atest" : "a";
    char encoded[110] = {0};
    const zxerr_t err = bech32EncodeFromBytes(encoded,
                                sizeof(encoded),
                                hrp,
                                tmpBuffer,
                                FIXED_LEN_STRING_BYTES,
                                0,
                                BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    pageString(outVal, outValLen, (const char*) encoded, pageIdx, pageCount);

    return parser_ok;
}

static parser_error_t printTimestamp(const prototimestamp_t *timestamp,
                                     char *outVal, uint16_t outValLen) {

    timedata_t date;
    if (extractTime(timestamp->seconds, &date) != zxerr_ok) {
        return parser_unexpected_error;
    }

    const uint64_t time = timestamp->seconds;
    printTime(outVal, outValLen, time);

    // YYYY-mm-dd HH:MM:SS.nnnnnnnnn UTC --> 33 chars
    snprintf(outVal, outValLen, "%04d-%02d-%02d %02d:%02d:%02d.%09d UTC",
             date.tm_year,
             date.tm_mon,
             date.tm_day,
             date.tm_hour, date.tm_min, date.tm_sec,
             timestamp->nanos);

    return parser_ok;
}

static parser_error_t printExpert( const parser_context_t *ctx,
                                   uint8_t displayIdx,
                                   char *outKey, uint16_t outKeyLen,
                                   char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount) {

    const wrapperTx_t *wrapperTx = &ctx->tx_obj->wrapperTx;
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Timestamp");
            CHECK_ERROR(printTimestamp(&ctx->tx_obj->innerTx.timestamp, outVal, outValLen))
            break;
        case 1: {
            const bytes_t *pubkey = &ctx->tx_obj->wrapperTx.pubkey;
            char hexString[67] = {0};
            snprintf(outKey, outKeyLen, "Pubkey");
            array_to_hexstr((char*) hexString, sizeof(hexString), pubkey->ptr, pubkey->len);
            pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            break;
        }
        case 2:
            snprintf(outKey, outKeyLen, "Epoch");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->wrapperTx.epoch) != NULL) {
                return parser_unexpected_error;
            }
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Gas limit");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->wrapperTx.gasLimit) != NULL) {
                return parser_unexpected_error;
            }
            break;
        case 4:
            snprintf(outKey, outKeyLen, "Fees");
            if (uint64_to_str(outVal, outValLen, wrapperTx->fees.amount) != NULL ||
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
                // Code should be already a hash -> Double hashing?
                const bytes_t *code_hash = &ctx->tx_obj->innerTx.code;
                snprintf(outKey, outKeyLen, "Code hash");
                array_to_hexstr((char*) hexString, sizeof(hexString), code_hash->ptr, code_hash->len);
                pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
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
            break;
        case 6:
            snprintf(outKey, outKeyLen, "Maximmum commission rate change");
            break;
        case 7:
            snprintf(outKey, outKeyLen, "Validator VP type");
            snprintf(outVal, outValLen, "User");
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

static parser_error_t printInitAccountTxn(  const parser_context_t *ctx,
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
                // Code should be already a hash -> Double hashing?
                const bytes_t *code_hash = &ctx->tx_obj->innerTx.code;
                snprintf(outKey, outKeyLen, "Code hash");
                array_to_hexstr((char*) hexString, sizeof(hexString), code_hash->ptr, code_hash->len);
                pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            }
            break;
        case 1:
            snprintf(outKey, outKeyLen, "Public key");
            const bytes_t *pubkey = &ctx->tx_obj->initAccount.pubkey;
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

static parser_error_t printWithdrawTxn( const parser_context_t *ctx,
                                        uint8_t displayIdx,
                                        char *outKey, uint16_t outKeyLen,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {

    // Bump itemIdx if source is not present
    if (ctx->tx_obj->withdraw.has_source == 0 && displayIdx >= 1) {
        displayIdx++;
    }

    char hexString[100] = {0};

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Withdraw");
            if (app_mode_expert()) {
                snprintf(outKey, outKeyLen, "Code hash");
                // Code should be already a hash -> Double hashing?
                const bytes_t *code_hash = &ctx->tx_obj->innerTx.code;
                array_to_hexstr((char*) hexString, sizeof(hexString), code_hash->ptr, code_hash->len);
                pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
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

static parser_error_t printBondTxn( const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    // Bump itemIdx if source is not present
    if (ctx->tx_obj->bond.has_source == 0 && displayIdx >= 1) {
        displayIdx++;
    }

    char hexString[100] = {0};

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Bond");
            if (ctx->tx_obj->typeTx == Unbond) {
                snprintf(outVal, outValLen, "Unbond");
            }
            if (app_mode_expert()) {
                // Code should be already a hash -> Double hashing?
                const bytes_t *code_hash = &ctx->tx_obj->innerTx.code;
                snprintf(outKey, outKeyLen, "Code hash");
                array_to_hexstr((char*) hexString, sizeof(hexString), code_hash->ptr, code_hash->len);
                pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
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

    // const wrapperTx_t *wrapperTx = &ctx->tx_obj->wrapperTx;
    char hexString[100] = {0};

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Transfer");
            if (app_mode_expert()) {
                // Code should be already a hash -> Double hashing?
                const bytes_t *code_hash = &ctx->tx_obj->innerTx.code;
                snprintf(outKey, outKeyLen, "Code hash");
                array_to_hexstr((char*) hexString, sizeof(hexString), code_hash->ptr, code_hash->len);
                pageString(outVal, outValLen, (const char*) &hexString, pageIdx, pageCount);
            }
            break;
        case 1:
            if (ctx->tx_obj->bond.has_source == 0) {
                return parser_unexpected_value;
            }
            snprintf(outKey, outKeyLen, "Sender");
            CHECK_ERROR(printAddress(ctx->tx_obj->transfer.source, outVal, outValLen, pageIdx, pageCount))
            break;
        case 2:
            snprintf(outKey, outKeyLen, "Destination");
            CHECK_ERROR(printAddress(ctx->tx_obj->transfer.target, outVal, outValLen, pageIdx, pageCount))
            break;
        case 3:
            snprintf(outKey, outKeyLen, "Amount");
            // Replace by printAmount --> include pagination and check token symbol
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transfer.amount) != NULL ||
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

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);


    switch (ctx->tx_obj->typeTx) {
        case Bond:
        case Unbond:
            return printBondTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Transfer:
            return printTransferTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitAccount:
            return printInitAccountTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Withdraw:
            return printWithdrawTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case InitValidator:
            return printInitValidatorTxn(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

