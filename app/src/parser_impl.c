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

#define TAG_CODE    0x0a
#define TAG_DATA    0x12
#define TAG_TS      0x1a
#define TAG_S       0x08
#define TAG_N       0x10
#define TAG_INNER_TX_HASH    0x22

#define ADDRESS_LEN_BYTES   45

#define BOND_NORMAL_PARAMS  3
#define BOND_EXPERT_PARAMS  8

#define TRANSFER_NORMAL_PARAMS  4
#define TRANSFER_EXPERT_PARAMS  9

#define INIT_ACCOUNT_NORMAL_PARAMS  2
#define INIT_ACCOUNT_EXPERT_PARAMS  7

#define WITHDRAW_NORMAL_PARAMS  2
#define WITHDRAW_EXPERT_PARAMS  7

#define INIT_VALIDATOR_NORMAL_PARAMS  8
#define INIT_VALIDATOR_EXPERT_PARAMS  13

#define SHA256_SIZE 32

static const uint8_t hash_bond[] = {0x74, 0xb0, 0xf3, 0x08, 0x73, 0x1c, 0xb5, 0x60, 0xd2, 0x4f, 0xc2, 0x69, 0x6d, 0x7e, 0x03, 0x6f, 0x25, 0x8c, 0x34, 0xfc, 0xe8, 0x6d, 0xdf, 0x9a, 0x6d, 0x66, 0xd2, 0xe4, 0x01, 0x95, 0xfb, 0x8b};
static const uint8_t hash_unbond[] = {0x41, 0x6f, 0x2d, 0x12, 0x09, 0x6a, 0x31, 0xc3, 0xd5, 0x8f, 0x79, 0x58, 0x2a, 0x40, 0x15, 0x21, 0x5b, 0xfc, 0xd4, 0xce, 0x6c, 0x34, 0x30, 0x6d, 0x92, 0x7f, 0xc5, 0xb0, 0xc8, 0xdd, 0x8f, 0xbf};
static const uint8_t hash_transfer[] = {0x53 ,0x0b ,0x8e ,0x4e ,0xfd ,0x28 ,0x48 ,0xd0 ,0x72 ,0x87 ,0x98 ,0xaa ,0xeb ,0xde ,0x64 ,0xa1 ,0x12 ,0xa6 ,0x46 ,0xf1 ,0xc1 ,0x1f ,0xba ,0x56 ,0xe6 ,0x4a ,0x12 ,0x5a ,0xa2 ,0x74 ,0xbb ,0x96};
static const uint8_t hash_init_account[] = {0x73 ,0xf3 ,0x05 ,0xf8 ,0x6c ,0xa2 ,0x44 ,0x02 ,0x2d ,0xab ,0x87 ,0xd7 ,0x53 ,0xc9 ,0x8d ,0x16 ,0xd7 ,0x90 ,0x36 ,0x4b ,0xfc ,0xe1 ,0xa0 ,0x36 ,0xdf ,0xa0 ,0x96 ,0xd0 ,0x4a ,0x28 ,0xee ,0xce};
static const uint8_t hash_withdraw[] = {0xdb ,0x7f ,0x9f ,0xda ,0x84 ,0xe8 ,0x77 ,0x8a ,0x92 ,0xdc ,0xdc ,0x74 ,0x73 ,0x6f ,0x4c ,0x8f ,0xa8 ,0x7d ,0xce ,0xac ,0xbf ,0x88 ,0xc4 ,0xbe ,0xa5 ,0x35 ,0xc9 ,0x7d ,0xaf ,0x07 ,0xbc ,0xfd};
static const uint8_t hash_init_validator[] = {0x9a ,0x14 ,0x03 ,0x43 ,0xf0 ,0xb1 ,0x5a ,0x97 ,0x28 ,0x3d ,0xe0 ,0xfd ,0xa9 ,0x9c ,0x0e ,0x8a ,0xf9 ,0xaa ,0xae ,0xbe ,0x5a ,0xfd ,0x3f ,0x17 ,0x33 ,0x56 ,0xf1 ,0x11 ,0xab ,0x82 ,0x07 ,0xc0};

static parser_error_t readByte(parser_context_t *ctx, uint8_t *byte) {
    if (byte == NULL || ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_error;
    }

    *byte = *(ctx->buffer + ctx->offset);
    ctx->offset++;
    return parser_ok;
}

static parser_error_t readUint64(parser_context_t *ctx, uint64_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint64_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint64_t));
    ctx->offset += sizeof(uint64_t);
    return parser_ok;
}

#define CHECK_TAG(CTX, TAG) {               \
    uint8_t tmpTag = 0;                     \
    CHECK_ERROR(readByte(CTX, &tmpTag))     \
    if (tmpTag != TAG) {                    \
        return parser_unexpected_value;     \
    }}



static parser_error_t readBytes(parser_context_t *ctx, const uint8_t **output, uint16_t outputLen) {
    if (ctx->offset + outputLen > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *output = ctx->buffer + ctx->offset;
    ctx->offset += outputLen;
    return parser_ok;
}

static parser_error_t readTransactionType(parser_tx_t *v) {
    // Bond
    if (!memcmp(v->innerTx.code.ptr, hash_bond, SHA256_SIZE)) {
        v->typeTx = Bond;
        return parser_ok;
    }
    // Unbond
    if (!memcmp(v->innerTx.code.ptr, hash_unbond, SHA256_SIZE)) {
        v->typeTx = Unbond;
        return parser_ok;
    }
    // Transfer
    if (!memcmp(v->innerTx.code.ptr, hash_transfer, SHA256_SIZE)) {
        v->typeTx = Transfer;
        return parser_ok;
    }
    // Init account
    if (!memcmp(v->innerTx.code.ptr, hash_init_account, SHA256_SIZE)) {
        v->typeTx = InitAccount;
        return parser_ok;
    }
    // Withdraw
    if (!memcmp(v->innerTx.code.ptr, hash_withdraw, SHA256_SIZE)) {
        v->typeTx = Withdraw;
        return parser_ok;
    }
    // Init validator
    if (!memcmp(v->innerTx.code.ptr, hash_init_validator, SHA256_SIZE)) {
        v->typeTx = InitValidator;
        return parser_ok;
    }

    return parser_unexpected_method;
}

static parser_error_t readInitValidatorTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    v->initValidator.account_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.account_key.ptr, v->initValidator.account_key.len))

    v->initValidator.consensus_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.consensus_key.ptr, v->initValidator.consensus_key.len))

    v->initValidator.protocol_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.protocol_key.ptr, v->initValidator.protocol_key.len))

    v->initValidator.dkg_key.len = 100; //Check this size. Is fixed?
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.dkg_key.ptr, v->initValidator.dkg_key.len))

    // Skip the rest of the fields
    ctx.offset = ctx.bufferLen;

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readInitAccountTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Pubkey
    if (ctx.bufferLen != 33) {
        return parser_unexpected_value;
    }
    v->initAccount.pubkey.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.pubkey.ptr, v->initAccount.pubkey.len))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readTransferTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Source
    v->transfer.source.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.source.ptr, v->transfer.source.len))

    // Target
    v->transfer.target.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.target.ptr, v->transfer.target.len))

    // Token
    v->transfer.token.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.token.ptr, v->transfer.token.len))

    // Subprefix: read until null terminator is found
    uint8_t tmp = 0;
    CHECK_ERROR(readByte(&ctx, &tmp))

    // Amount
    CHECK_ERROR(readUint64(&ctx, &v->transfer.amount))

    ctx.offset += 2;   // Skip last 2 bytes --> Check this

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readWithdrawTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->withdraw.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->bond.validator.ptr, v->bond.validator.len))

    ctx.offset++;  // Skip byte --> Check this

    // Source
    if (ctx.offset < ctx.bufferLen) {
        v->withdraw.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->withdraw.source.ptr, v->withdraw.source.len))
        v->withdraw.has_source = 1;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readBondTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->bond.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->bond.validator.ptr, v->bond.validator.len))

    // Amount
    MEMCPY(&v->bond.amount, ctx.buffer + ctx.offset, sizeof(uint64_t));
    ctx.offset += sizeof(uint64_t);
    ctx.offset++;   // Skip last byte --> Check this

    // Source
    if (ctx.offset < ctx.bufferLen) {
        v->bond.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->bond.source.ptr, v->bond.source.len))
        v->bond.has_source = 1;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readTimestamp(parser_context_t *ctx, prototimestamp_t *timestamp) {
    uint64_t timestampSize = 0;
    uint8_t consumed = 0;
    uint64_t tmp = 0;

    // Timestamp
    CHECK_TAG(ctx, TAG_TS)
    decodeLEB128(ctx->buffer + ctx->offset, 10, &consumed, &timestampSize);
    ctx->offset += consumed;

    // Seconds
    CHECK_TAG(ctx, TAG_S)
    decodeLEB128(ctx->buffer + ctx->offset, timestampSize, &consumed, &timestamp->seconds);
    ctx->offset += consumed;

    // Nanos
    CHECK_TAG(ctx, TAG_N)
    decodeLEB128(ctx->buffer + ctx->offset, timestampSize, &consumed, &tmp);
    ctx->offset += consumed;
    if (tmp > UINT32_MAX) {
        return parser_value_out_of_range;
    }
    timestamp->nanos = (uint32_t) tmp;

    return parser_ok;
}

__Z_INLINE parser_error_t readFieldSize(parser_context_t *ctx, uint32_t *size) {
    uint8_t consumed = 0;
    uint64_t tmpSize = 0;

    decodeLEB128(ctx->buffer + ctx->offset, 10, &consumed, &tmpSize);
    ctx->offset += consumed;

    if (tmpSize > UINT32_MAX) {
        return parser_value_out_of_range;
    }
    *size = (uint32_t)tmpSize;

    return parser_ok;
}

__Z_INLINE parser_error_t readInnerTx(parser_context_t *ctx, parser_tx_t *v) {
    // Code
    CHECK_TAG(ctx, TAG_CODE)
    CHECK_ERROR(readFieldSize(ctx, &v->innerTx.code.len))
    CHECK_ERROR(readBytes(ctx, &v->innerTx.code.ptr, v->innerTx.code.len))

    // Data
    CHECK_TAG(ctx, TAG_DATA)
    CHECK_ERROR(readFieldSize(ctx, &v->innerTx.data.len))
    CHECK_ERROR(readBytes(ctx, &v->innerTx.data.ptr, v->innerTx.data.len))

    // Timestamp
    CHECK_ERROR(readTimestamp(ctx, &v->innerTx.timestamp))

    // Read inner txn params
    CHECK_ERROR(readTransactionType(v))
    switch (v->typeTx) {
        case Bond:
        case Unbond:
            CHECK_ERROR(readBondTxn(&v->innerTx.data, v))
            break;
        case Transfer:
            CHECK_ERROR(readTransferTxn(&v->innerTx.data, v))
            break;
        case InitAccount:
            CHECK_ERROR(readInitAccountTxn(&v->innerTx.data, v))
            break;
        case Withdraw:
            CHECK_ERROR(readWithdrawTxn(&v->innerTx.data, v))
            break;
        case InitValidator:
            CHECK_ERROR(readInitValidatorTxn(&v->innerTx.data, v))
            break;
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readWrapperTx(parser_context_t *ctx, parser_tx_t *v) {
    // Dummy innerTx hash
    CHECK_TAG(ctx, TAG_INNER_TX_HASH)
    CHECK_ERROR(readFieldSize(ctx, &v->wrapperTx.innerTxHash.len))
    if (v->wrapperTx.innerTxHash.len != 32) {
        return parser_value_out_of_range;
    }
    CHECK_ERROR(readBytes(ctx, &v->wrapperTx.innerTxHash.ptr, v->wrapperTx.innerTxHash.len))

    // Fee.amount
    CHECK_ERROR(readUint64(ctx, &v->wrapperTx.fees.amount))
    // Fee.address
    v->wrapperTx.fees.address.len = 45;
    CHECK_ERROR(readBytes(ctx, &v->wrapperTx.fees.address.ptr, v->wrapperTx.fees.address.len))
    // Pubkey
    v->wrapperTx.pubkey.len = 33;
    CHECK_ERROR(readBytes(ctx, &v->wrapperTx.pubkey.ptr, v->wrapperTx.pubkey.len))
    // Epoch
    CHECK_ERROR(readUint64(ctx, &v->wrapperTx.epoch))
    // GasLimit
    CHECK_ERROR(readUint64(ctx, &v->wrapperTx.gasLimit))

    // Check final bytes
    ctx->offset = ctx->bufferLen;

    return parser_ok;
}

parser_error_t _read(parser_context_t *ctx, parser_tx_t *v) {
    // Read InnerTx
    CHECK_ERROR(readInnerTx(ctx, v))

    // Read WrapperTx
    v->wrapperTx.startData = ctx->buffer + ctx->offset;
    CHECK_ERROR(readWrapperTx(ctx, v))

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
