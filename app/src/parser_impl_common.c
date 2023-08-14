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
#include "parser_impl_common.h"
#include "leb128.h"

#define SIGN_MASK 0x80000000
#define SCALE_SHIFT 16

parser_error_t readByte(parser_context_t *ctx, uint8_t *byte) {
    if (byte == NULL || ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_error;
    }

    *byte = *(ctx->buffer + ctx->offset);
    ctx->offset++;
    return parser_ok;
}

parser_error_t readUint16(parser_context_t *ctx, uint16_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint16_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint16_t));
    ctx->offset += sizeof(uint16_t);
    return parser_ok;
}

parser_error_t readUint32(parser_context_t *ctx, uint32_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint32_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint32_t));
    ctx->offset += sizeof(uint32_t);
    return parser_ok;
}

parser_error_t readUint64(parser_context_t *ctx, uint64_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint64_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint64_t));
    ctx->offset += sizeof(uint64_t);
    return parser_ok;
}

parser_error_t readUint256(parser_context_t *ctx, uint256_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint256_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint256_t));
    ctx->offset += sizeof(uint256_t);
    return parser_ok;
}

zxerr_t recover_decimal(const uint8_t* bytes, int64_t* num, uint32_t* scale) {
    if (bytes == NULL) {
        return zxerr_unknown; // Invalid byte sequence
    }

    uint32_t flag = 0;
    for (int i = 0; i < 4; i++) {
        flag |= ((uint32_t)bytes[i]) << (8 * i);
    }

    *scale = (flag >> SCALE_SHIFT);
    uint8_t is_negative = (flag & SIGN_MASK) != 0;

    uint32_t hi = 0, lo = 0, mid = 0;
    for (int i = 0; i < 4; i++) {
        hi |= ((uint32_t)bytes[4 + i]) << (8 * i);
        lo |= ((uint32_t)bytes[8 + i]) << (8 * i);
        mid |= ((uint32_t)bytes[12 + i]) << (8 * i);
    }

    uint64_t m = ((uint64_t)hi) << 32 | lo;
    m |= ((uint64_t)mid) << 32;

    if (is_negative) {
        m = ~m + 1; // Two's complement negation
    }

    *num = (int64_t)m;
    return zxerr_ok;
}

parser_error_t readDecimal(parser_context_t *ctx, serialized_decimal *value) {
    if (value == NULL || ctx->offset + sizeof(serialized_decimal) > ctx->bufferLen) {
        return parser_unexpected_error;
    }
    uint8_t raw_decimal[sizeof(serialized_decimal)] = {0};
    MEMCPY(raw_decimal, ctx->buffer + ctx->offset, sizeof(serialized_decimal));

    recover_decimal((const uint8_t *) &raw_decimal, &value->num, &value->scale);

    ctx->offset += sizeof(serialized_decimal);
    return parser_ok;
}


parser_error_t readBytes(parser_context_t *ctx, const uint8_t **output, uint16_t outputLen) {
    if (ctx->offset + outputLen > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *output = ctx->buffer + ctx->offset;
    ctx->offset += outputLen;
    return parser_ok;
}

parser_error_t readFieldSize(parser_context_t *ctx, uint32_t *size) {
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

parser_error_t checkTag(parser_context_t *ctx, uint8_t expectedTag) {
    uint8_t tmpTag = 0;
    CHECK_ERROR(readByte(ctx, &tmpTag))

    if (tmpTag != expectedTag) {
        return parser_unexpected_value;
    }
    return parser_ok;
}
