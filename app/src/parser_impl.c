/*******************************************************************************
*  (c) 2018 - 2022 Zondax AG
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

parser_error_t _read(parser_context_t *c, parser_tx_t *v)
{
    if (c->bufferLen < v->outerTxnPtr->codeSize + v->outerTxnPtr->dataSize + sizeof(uint64_t) + sizeof(uint32_t)) {
        return parser_missing_field;
    }
    // Point data from input buffer to OuterTxn struct
    v->outerTxnPtr->code = c->buffer;
    v->outerTxnPtr->data = c->buffer + v->outerTxnPtr->codeSize;
    MEMCPY(&v->outerTxnPtr->timestamp, v->outerTxnPtr->data + v->outerTxnPtr->dataSize, 12);

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
