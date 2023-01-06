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


parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    ctx->tx_obj->outerTxnPtr = &outerTxn;
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
    // #{TODO} --> function to retrieve num Items
    // *num_items = _getNumItems();
    *num_items = 4;
    if(*num_items == 0) {
        return parser_unexpected_number_items;
    }
    return parser_ok;
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

    const outer_layer_tx_t *outerTxn = ctx->tx_obj->outerTxnPtr;
    switch (displayIdx)
    {
        case 0:
            snprintf(outKey, outKeyLen, "Code");
            pageStringExt(outVal, outValLen, (const char*) outerTxn->code, outerTxn->codeSize, pageIdx, pageCount);
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "Data");
            pageStringExt(outVal, outValLen, (const char*) outerTxn->data, outerTxn->dataSize, pageIdx, pageCount);
            return parser_ok;
        case 2:
            snprintf(outKey, outKeyLen, "Seconds");
            if (uint64_to_str(outVal, outValLen, outerTxn->timestamp.seconds) == NULL) {
                return parser_ok;
            }
            return parser_no_data;
        case 3:
            snprintf(outKey, outKeyLen, "Nanos");
            snprintf(outVal, outValLen, "%d", ctx->tx_obj->outerTxnPtr->timestamp.nanos);
            return parser_ok;
    default:
        break;
    }

    return parser_display_idx_out_of_range;
}

