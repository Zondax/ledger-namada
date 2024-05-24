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
#include "txn_validator.h"
#include "parser_impl_common.h"
#include "zxmacros.h"
#include "parser_address.h"

parser_error_t readBecomeValidator(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    CHECK_ERROR(readAddressAlt(&ctx, &v->becomeValidator.address))

    CHECK_ERROR(readPubkey(&ctx, &v->becomeValidator.consensus_key))

    v->becomeValidator.eth_cold_key.len = COMPRESSED_SECP256K1_PK_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.eth_cold_key.ptr, v->becomeValidator.eth_cold_key.len))

    v->becomeValidator.eth_hot_key.len = COMPRESSED_SECP256K1_PK_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.eth_hot_key.ptr, v->becomeValidator.eth_hot_key.len))

    CHECK_ERROR(readPubkey(&ctx, &v->becomeValidator.protocol_key))

    // Commission rate
    v->becomeValidator.commission_rate.len = 32;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.commission_rate.ptr, v->becomeValidator.commission_rate.len))

    // Max commission rate change
    v->becomeValidator.max_commission_rate_change.len = 32;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.max_commission_rate_change.ptr, v->becomeValidator.max_commission_rate_change.len))

    uint32_t tmpValue = 0;
    // The validator email
    CHECK_ERROR(readUint32(&ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    v->becomeValidator.email.len = (uint16_t)tmpValue;
    CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.email.ptr, v->becomeValidator.email.len))

    /// The validator description
    v->becomeValidator.description.ptr = NULL;
    v->becomeValidator.description.len = 0;
    uint8_t has_description = 0;
    CHECK_ERROR(readByte(&ctx, &has_description))
    if (has_description != 0 && has_description != 1) {
        return parser_value_out_of_range;
    }

    if (has_description) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.description.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.description.ptr, v->becomeValidator.description.len))
    }

    /// The validator website
    v->becomeValidator.website.ptr = NULL;
    v->becomeValidator.website.len = 0;
    uint8_t has_website;
    CHECK_ERROR(readByte(&ctx, &has_website))
    if (has_website) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.website.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.website.ptr, v->becomeValidator.website.len))
    }

    /// The validator's discord handle
    v->becomeValidator.discord_handle.ptr = NULL;
    v->becomeValidator.discord_handle.len = 0;
    uint8_t has_discord_handle;
    CHECK_ERROR(readByte(&ctx, &has_discord_handle))
    if (has_discord_handle) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.discord_handle.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.discord_handle.ptr, v->becomeValidator.discord_handle.len))
    }

    /// The validator's avatar
    v->becomeValidator.avatar.ptr = NULL;
    v->becomeValidator.avatar.len = 0;
    uint8_t has_avatar;
    CHECK_ERROR(readByte(&ctx, &has_avatar))
    if (has_avatar) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.avatar.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.avatar.ptr, v->becomeValidator.avatar.len))
    }

    /// The validator's name
    v->becomeValidator.name.ptr = NULL;
    v->becomeValidator.name.len = 0;
    uint8_t has_name;
    CHECK_ERROR(readByte(&ctx, &has_name))
    if (has_name) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->becomeValidator.name.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &v->becomeValidator.name.ptr, v->becomeValidator.name.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

parser_error_t readUnjailValidator(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Address
    CHECK_ERROR(readAddressAlt(&ctx, &v->unjailValidator.validator))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

parser_error_t readActivateValidator(const bytes_t *data, tx_activate_validator_t *txObject) {
    if (data == NULL || txObject == NULL) {
        return parser_unexpected_error;
    }

    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Address
    CHECK_ERROR(readAddressAlt(&ctx, &txObject->validator))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
