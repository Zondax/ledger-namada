/*******************************************************************************
*  (c) 2018 - 2024 Zondax AG
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

bool isAllZeroes(const void *buf, size_t n) {
    uint8_t *p = (uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i]) {
            return false;
        }
    }
    return true;
}

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

parser_error_t readBytes(parser_context_t *ctx, const uint8_t **output, uint16_t outputLen) {
    if (ctx->offset + outputLen > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *output = ctx->buffer + ctx->offset;
    ctx->offset += outputLen;
    return parser_ok;
}

parser_error_t readBytesSize(parser_context_t *ctx, uint8_t *output, uint16_t outputLen) {
    if (ctx->offset + outputLen > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    MEMCPY(output, (ctx->buffer + ctx->offset), outputLen);
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

parser_error_t readFieldSizeU16(parser_context_t *ctx, uint16_t *size) {
    uint8_t consumed = 0;
    uint64_t tmpSize = 0;

    decodeLEB128(ctx->buffer + ctx->offset, 10, &consumed, &tmpSize);
    ctx->offset += consumed;

    if (tmpSize > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    *size = (uint16_t)tmpSize;

    return parser_ok;
}

parser_error_t readCompactSize(parser_context_t *ctx, uint64_t *result) {
    uint8_t tag = 0;
    uint16_t tmp16 = 0;
    uint32_t tmp32 = 0;
    CHECK_ERROR(readByte(ctx, &tag))
    switch(tag) {
    case 253:
        CHECK_ERROR(readUint16(ctx, &tmp16))
        *result = (uint64_t)tmp16;
        break;
    case 254:
        CHECK_ERROR(readUint32(ctx, &tmp32))
        *result = (uint64_t)tmp32;
        break;
    case 255:
        CHECK_ERROR(readUint64(ctx, result))
        break;
    default:
        *result = (uint64_t)tag;
    }
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

parser_error_t readPubkey(parser_context_t *ctx, bytes_t *pubkey) {
    if (ctx == NULL || pubkey == NULL) {
        return parser_unexpected_buffer_end;
    }

    if (ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    const uint8_t pkType = *(ctx->buffer + ctx->offset);
    //Pubkey must include pkType (needed for encoding)
    pubkey->len = 1 + (pkType == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN);
    CHECK_ERROR(readBytes(ctx, &pubkey->ptr, pubkey->len))
    return parser_ok;
}
