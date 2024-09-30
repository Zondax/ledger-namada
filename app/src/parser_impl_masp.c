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
#include "parser_impl_masp.h"
#include "coin.h"
#include "parser_impl_common.h"
#include "parser_txdef.h"
#include "nvdata.h"
#include "crypto_helper.h"
#include "parser_address.h"
#include "tx_hash.h"

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    #include "cx.h"
    #include "cx_sha256.h"
    #include "cx_blake2b.h"
#endif

static parser_error_t readSaplingBundle(parser_context_t *ctx, masp_sapling_bundle_t *bundle) {
    if (ctx == NULL || bundle == NULL) {
        return parser_unexpected_error;
    }

    // Read spends
    CHECK_ERROR(readCompactSize(ctx, &bundle->n_shielded_spends))
    if (bundle->n_shielded_spends != 0) {
        bundle->shielded_spends.len = SHIELDED_SPENDS_LEN * bundle->n_shielded_spends;
        CHECK_ERROR(readBytes(ctx, &bundle->shielded_spends.ptr, bundle->shielded_spends.len))
    }

    // Read converts
    CHECK_ERROR(readCompactSize(ctx, &bundle->n_shielded_converts))
    if (bundle->n_shielded_converts != 0) {
        bundle->shielded_converts.len = SHIELDED_CONVERTS_LEN * bundle->n_shielded_converts;
        CHECK_ERROR(readBytes(ctx, &bundle->shielded_converts.ptr, bundle->shielded_converts.len))
    }

    // Read outputs
    CHECK_ERROR(readCompactSize(ctx, &bundle->n_shielded_outputs))
    if (bundle->n_shielded_outputs != 0) {
        bundle->shielded_outputs.len = SHIELDED_OUTPUTS_LEN * bundle->n_shielded_outputs;
        CHECK_ERROR(readBytes(ctx, &bundle->shielded_outputs.ptr, bundle->shielded_outputs.len))
    }

    // Read Value sum
    if (bundle->n_shielded_spends != 0 || bundle->n_shielded_outputs != 0 || bundle->n_shielded_converts != 0) {
        CHECK_ERROR(readCompactSize(ctx, &bundle->n_value_sum_asset_type))
        bundle->value_sum_asset_type.len = (ASSET_ID_LEN + INT_128_LEN) * bundle->n_value_sum_asset_type;
        CHECK_ERROR(readBytes(ctx, &bundle->value_sum_asset_type.ptr, bundle->value_sum_asset_type.len))
    }

    // Read spend Anchor
    if (bundle->n_shielded_spends != 0) {
        bundle->anchor_shielded_spends.len = ANCHOR_LEN;
        CHECK_ERROR(readBytes(ctx, &bundle->anchor_shielded_spends.ptr, bundle->anchor_shielded_spends.len))
    }

    // Read convert Anchor
    if (bundle->n_shielded_converts != 0) {
        bundle->anchor_shielded_converts.len = ANCHOR_LEN;
        CHECK_ERROR(readBytes(ctx, &bundle->anchor_shielded_converts.ptr, bundle->anchor_shielded_converts.len))
    }

    // Read spends proofs
    if (bundle->n_shielded_spends != 0) {
        bundle->zkproof_shielded_spends.len = ZKPROFF_LEN * bundle->n_shielded_spends;
        CHECK_ERROR(readBytes(ctx, &bundle->zkproof_shielded_spends.ptr, bundle->zkproof_shielded_spends.len))
        bundle->auth_sig_shielded_spends.len = AUTH_SIG_LEN * bundle->n_shielded_spends;
        CHECK_ERROR(readBytes(ctx, &bundle->auth_sig_shielded_spends.ptr, bundle->auth_sig_shielded_spends.len))
    }

    // Read converts proofs
    if (bundle->n_shielded_converts != 0) {
        bundle->zkproof_shielded_converts.len = ZKPROFF_LEN * bundle->n_shielded_converts;
        CHECK_ERROR(readBytes(ctx, &bundle->zkproof_shielded_converts.ptr, bundle->zkproof_shielded_converts.len))
    }

    // Read outputs proofs
    if (bundle->n_shielded_outputs != 0) {
        bundle->zkproof_shielded_outputs.len = ZKPROFF_LEN * bundle->n_shielded_outputs;
        CHECK_ERROR(readBytes(ctx, &bundle->zkproof_shielded_outputs.ptr, bundle->zkproof_shielded_outputs.len))
    }

    // Read authorization signature
    if (bundle->n_shielded_outputs != 0 || bundle->n_shielded_spends != 0 || bundle->n_shielded_converts != 0) {
        bundle->authorization.len = AUTH_SIG_LEN;
        CHECK_ERROR(readBytes(ctx, &bundle->authorization.ptr, bundle->authorization.len))
    }

    return parser_ok;
}

static parser_error_t readTransparentBundle(parser_context_t *ctx, masp_transparent_bundle_t *bundle) {
    if (ctx == NULL || bundle == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readCompactSize(ctx, &bundle->n_vin))
    bundle->vin.len = bundle->n_vin * TXIN_AUTH_LEN;
    CHECK_ERROR(readBytes(ctx, &bundle->vin.ptr, bundle->vin.len))

    CHECK_ERROR(readCompactSize(ctx, &bundle->n_vout))
    bundle->vout.len = bundle->n_vout * TXOUT_AUTH_LEN;
    CHECK_ERROR(readBytes(ctx, &bundle->vout.ptr, bundle->vout.len))
    return parser_ok;
}

static parser_error_t readSaplingMetadata(parser_context_t *ctx, masp_sapling_metadata_t *metadata) {
    if (ctx == NULL || metadata == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readUint32(ctx, &metadata->n_spends_indices))
    if (metadata->n_spends_indices != 0) {
        metadata->spends_indices.len = metadata->n_spends_indices * sizeof(uint64_t);
        CHECK_ERROR(readBytes(ctx, &metadata->spends_indices.ptr, metadata->spends_indices.len))
    }

    CHECK_ERROR(readUint32(ctx, &metadata->n_converts_indices))
    if (metadata->n_converts_indices != 0) {
        metadata->converts_indices.len = metadata->n_converts_indices * sizeof(uint64_t);
        CHECK_ERROR(readBytes(ctx, &metadata->converts_indices.ptr, metadata->converts_indices.len))
    }

    CHECK_ERROR(readUint32(ctx, &metadata->n_outputs_indices))
    if (metadata->n_outputs_indices != 0) {
        metadata->outputs_indices.len = metadata->n_outputs_indices * sizeof(uint64_t);
        CHECK_ERROR(readBytes(ctx, &metadata->outputs_indices.ptr, metadata->outputs_indices.len))
    }

    return parser_ok;
}

static parser_error_t readTransparentBuilder(parser_context_t *ctx, masp_transparent_builder_t *builder) {
    if (ctx == NULL || builder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readUint32(ctx, &builder->n_inputs))
    if (builder->n_inputs != 0) {
        builder->inputs.len = builder->n_inputs * TXOUT_AUTH_LEN;
        CHECK_ERROR(readBytes(ctx, &builder->inputs.ptr, builder->inputs.len))
    }

    CHECK_ERROR(readUint32(ctx, &builder->n_vout))
    if (builder->n_vout != 0) {
        builder->vout.len = builder->n_vout * TXOUT_AUTH_LEN;
        CHECK_ERROR(readBytes(ctx, &builder->vout.ptr, builder->vout.len))
    }
    return parser_ok;
}


static parser_error_t readSpendDescriptionInfo(parser_context_t *ctx, masp_sapling_builder_t *builder) {
    if (ctx == NULL || builder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readUint32(ctx, &builder->n_spends))
#if defined(LEDGER_SPECIFIC) && !defined(APP_TESTING)
    if (G_io_apdu_buffer[OFFSET_INS] == INS_SIGN_MASP_SPENDS) {
        uint32_t rnd_spends = (uint32_t)transaction_get_n_spends();
        if (rnd_spends < builder->n_spends) {
            return parser_invalid_number_of_spends;
        }
    }
#endif

    // Get start pointer and offset to later calculate the size of the spends
    builder->spends.ptr = ctx->buffer + ctx->offset;
    uint16_t tmp_offset = ctx->offset;
    uint64_t tmp_64 = 0;
    uint8_t tmp_8 = 0;
    bytes_t tmp = {0};
    for(uint32_t i = 0; i < builder->n_spends; i++) {

        // parse Extyended Full Viewing Key
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, EXTENDED_FVK_LEN))

        //parse diversifier
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, DIVERSIFIER_LEN))

        //parse note
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, NOTE_LEN))

        // Parse Merkle path
        CHECK_ERROR(readByte(ctx, &tmp_8))
        tmp.len = tmp_8 * (32 + 1);
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, tmp.len))
        CHECK_ERROR(readUint64(ctx, &tmp_64))
    }

    builder->spends.len = ctx->offset - tmp_offset;
    return parser_ok;
}

parser_error_t getSpendDescriptionLen(const uint8_t *spend, uint16_t *len) {
    if (spend == NULL || len == NULL) {
        return parser_unexpected_error;
    }

    uint16_t offset = EXTENDED_FVK_LEN + DIVERSIFIER_LEN + NOTE_LEN;
    spend += offset;
    uint8_t auth_path_len = *spend;
    *len = offset + 1 + (auth_path_len * (32 + 1)) + POSITION_LEN;

    return parser_ok;
}

parser_error_t getNextSpendDescription(parser_context_t *spend, uint8_t index) {
    if (spend == NULL) {
        return parser_unexpected_error;
    }

    for (int i = 0 ; i< index; i++) {
        CTX_CHECK_AND_ADVANCE(spend, EXTENDED_FVK_LEN + DIVERSIFIER_LEN + NOTE_LEN);
        uint8_t auth_path_len = 0;
        CHECK_ERROR(readByte(spend, &auth_path_len))
        CTX_CHECK_AND_ADVANCE(spend, (auth_path_len * (32 + 1)) + POSITION_LEN);
    }

    return parser_ok;
}

parser_error_t getNextOutputDescription(parser_context_t *output, uint8_t index) {
    if (output == NULL) {
        return parser_unexpected_error;
    }

    for (int i = 0; i < index; i++) {
        uint8_t has_ovk = 0;
        CHECK_ERROR(readByte(output, &has_ovk));
        CTX_CHECK_AND_ADVANCE(output, (has_ovk ? 32 : 0) + DIVERSIFIER_LEN + PAYMENT_ADDR_LEN + OUT_NOTE_LEN + MEMO_LEN);
    }
    return parser_ok;
}

parser_error_t getNextConvertDescription(parser_context_t *convert, uint8_t index) {
    if (convert == NULL) {
        return parser_unexpected_error;
    }
    uint64_t allowed_size = 0;
    uint16_t tmp16 = 0;
    uint32_t tmp32 = 0;
    uint8_t merkel_size = 0;
    uint8_t tag = 0;
    for (int i = 0; i < index; i++) {
        CHECK_ERROR(readByte(convert, &tag));

        switch(tag) {
        case 253:
            CHECK_ERROR(readUint16(convert, &tmp16));
            allowed_size = (uint64_t)tmp16;
            break;
        case 254:
            CHECK_ERROR(readUint32(convert, &tmp32));
            allowed_size = (uint64_t)tmp32;
            break;
        case 255:
            CHECK_ERROR(readUint64(convert, &allowed_size));
            break;
        default:
            allowed_size = (uint64_t)tag;
        }
        CTX_CHECK_AND_ADVANCE(convert, allowed_size * (ASSET_ID_LEN + INT_128_LEN) + sizeof(uint64_t));
        CTX_CHECK_AND_ADVANCE(convert, 32);
        CHECK_ERROR(readByte(convert, &merkel_size));
        CTX_CHECK_AND_ADVANCE(convert, merkel_size * (32 + 1) + sizeof(uint64_t));
    }

    return parser_ok;
}

static parser_error_t readConvertDescriptionInfo(parser_context_t *ctx, masp_sapling_builder_t *builder) {
    if (ctx == NULL || builder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readUint32(ctx, &builder->n_converts))
#if defined(LEDGER_SPECIFIC) && !defined(APP_TESTING)
    if (G_io_apdu_buffer[OFFSET_INS] == INS_SIGN_MASP_SPENDS) {
        uint32_t rnd_converts = (uint32_t)transaction_get_n_converts();
        if (rnd_converts < builder->n_converts) {
            return parser_invalid_number_of_converts;
        }
    }
#endif

    // Get start pointer and offset to later calculate the size of the converts
    builder->converts.ptr = ctx->buffer + ctx->offset;
    uint16_t tmp_offset = ctx->offset;

    uint8_t tmp_8 = 0;
    uint64_t tmp_64 = 0;
    bytes_t tmp = {0};
    for (uint32_t i = 0; i < builder->n_converts; i++) {

        // Parse Allowed conversion
        CHECK_ERROR(readCompactSize(ctx, &tmp_64))
        tmp.len = tmp_64 * (ASSET_ID_LEN + INT_128_LEN);
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, tmp.len))

        // Parse value
        CHECK_ERROR(readUint64(ctx, &tmp_64))

        // Parse generator
        tmp.len = 32;
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, tmp.len))

        // Parse Merkle path
        CHECK_ERROR(readByte(ctx, &tmp_8))
        tmp.len = tmp_8 * (32 + 1);
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, tmp.len))
        CHECK_ERROR(readUint64(ctx, &tmp_64))
    }

    builder->converts.len = ctx->offset - tmp_offset;
    return parser_ok;
}

static parser_error_t readSaplingOutputDescriptionInfo(parser_context_t *ctx, masp_sapling_builder_t *builder) {
    if (ctx == NULL || builder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readUint32(ctx, &builder->n_outputs))
#if defined(LEDGER_SPECIFIC) && !defined(APP_TESTING)
    if (G_io_apdu_buffer[OFFSET_INS] == INS_SIGN_MASP_SPENDS) {
        uint32_t rnd_outputs = (uint32_t)transaction_get_n_outputs();
        if (rnd_outputs < builder->n_outputs) {
            return parser_invalid_number_of_outputs;
        }
    }
#endif

    // Get start pointer and offset to later calculate the size of the outputs
    builder->outputs.ptr = ctx->buffer + ctx->offset;
    uint16_t tmp_offset = ctx->offset;

    bytes_t tmp = {0};
    for (uint32_t i = 0; i < builder->n_outputs; i++) {
        CHECK_ERROR(readByte(ctx, &builder->has_ovk))
        if (builder->has_ovk) {
            // Parse ovk
            CHECK_ERROR(readBytes(ctx, &tmp.ptr, OVK_LEN))
        }

        // Parse payment address
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, DIVERSIFIER_LEN))
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, PAYMENT_ADDR_LEN))

        // read note
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, OUT_NOTE_LEN))

        // Parse memo
        CHECK_ERROR(readBytes(ctx, &tmp.ptr, MEMO_LEN))
    }

    builder->outputs.len = ctx->offset - tmp_offset;

    return parser_ok;
}

static parser_error_t readSaplingBuilder(parser_context_t *ctx, masp_sapling_builder_t *builder) {
    if (ctx == NULL || builder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &builder->has_spend_anchor))
    if (builder->has_spend_anchor) {
        builder->spend_anchor.len = ANCHOR_LEN;
        CHECK_ERROR(readBytes(ctx, &builder->spend_anchor.ptr, builder->spend_anchor.len))
    }

    CHECK_ERROR(readUint32(ctx, &builder->target_height))

    CHECK_ERROR(readCompactSize(ctx, &builder->n_value_sum_asset_type))
    builder->value_sum_asset_type.len = (ASSET_ID_LEN + INT_128_LEN) * builder->n_value_sum_asset_type;
    CHECK_ERROR(readBytes(ctx, &builder->value_sum_asset_type.ptr, builder->value_sum_asset_type.len))

    CHECK_ERROR(readByte(ctx, &builder->has_convert_anchor))
    if (builder->has_convert_anchor) {
        builder->convert_anchor.len = ANCHOR_LEN;
        CHECK_ERROR(readBytes(ctx, &builder->convert_anchor.ptr, builder->convert_anchor.len))
    }

    CHECK_ERROR(readSpendDescriptionInfo(ctx, builder))
    CHECK_ERROR(readConvertDescriptionInfo(ctx, builder))
    CHECK_ERROR(readSaplingOutputDescriptionInfo(ctx, builder))

    return parser_ok;
}

static parser_error_t readBuilder(parser_context_t *ctx, masp_builder_t *builder) {
    if (ctx == NULL || builder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readUint32(ctx, &builder->target_height))
    CHECK_ERROR(readUint32(ctx, &builder->expiry_height))

    CHECK_ERROR(readTransparentBuilder(ctx, &builder->transparent_builder))
    CHECK_ERROR(readSaplingBuilder(ctx, &builder->sapling_builder))

    return parser_ok;
}

parser_error_t readMaspTx(parser_context_t *ctx, masp_tx_section_t *maspTx) {
    if (ctx == NULL || maspTx == NULL) {
        return parser_unexpected_error;
    }
    maspTx->masptx_ptr = ctx->buffer + ctx->offset;

    uint8_t sectionMaspTx = 0;
    CHECK_ERROR(readByte(ctx, &sectionMaspTx))
    if (sectionMaspTx != DISCRIMINANT_MASP_TX) {
        return parser_unexpected_value;
    }

    // Read version for now only MaspV5 that translates to 0x02
    CHECK_ERROR(readUint32(ctx, &maspTx->data.tx_version))
    if (maspTx->data.tx_version != MASPV5_TX_VERSION) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readUint32(ctx, &maspTx->data.version_group_id))
    if (maspTx->data.version_group_id != MASPV5_VERSION_GROUP_ID) {
        return parser_unexpected_value;
    }

    // Read branch id, unique enum for now
    CHECK_ERROR(readUint32(ctx, &maspTx->data.consensus_branch_id))
    if (maspTx->data.consensus_branch_id != BRANCH_ID_IDENTIFIER) {
        return parser_unexpected_value;
    }

    // Read lock time
    CHECK_ERROR(readUint32(ctx, &maspTx->data.lock_time))

    // Read expiry_height
    CHECK_ERROR(readUint32(ctx, &maspTx->data.expiry_height))

    // Read transparent bundle
    CHECK_ERROR(readTransparentBundle(ctx, &maspTx->data.transparent_bundle))

    // Read sapling bundle
    CHECK_ERROR(readSaplingBundle(ctx, &maspTx->data.sapling_bundle))

    maspTx->masptx_len = ctx->buffer + ctx->offset - maspTx->masptx_ptr;
    return parser_ok;
}

parser_error_t readMaspBuilder(parser_context_t *ctx, masp_builder_section_t *maspBuilder) {
    if (ctx == NULL || maspBuilder == NULL) {
        return parser_unexpected_error;
    }

    uint8_t sectionMaspTx = 0;
    CHECK_ERROR(readByte(ctx, &sectionMaspTx))
    if (sectionMaspTx != DISCRIMINANT_MASP_BUILDER) {
        return parser_unexpected_value;
    }

    maspBuilder->target_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->target_hash.ptr, maspBuilder->target_hash.len))

    CHECK_ERROR(readUint32(ctx, &maspBuilder->n_asset_type))
    maspBuilder->asset_data.ptr = ctx->buffer + ctx->offset;
    for (uint32_t i = 0; i < maspBuilder->n_asset_type; i++) {
        masp_asset_data_t asset_data;
        CHECK_ERROR(readAssetData(ctx, &asset_data))
    }
    maspBuilder->asset_data.len = ctx->buffer + ctx->offset - maspBuilder->asset_data.ptr;

    CHECK_ERROR(readSaplingMetadata(ctx, &maspBuilder->metadata))
    CHECK_ERROR(readBuilder(ctx, &maspBuilder->builder))

    return parser_ok;
}

parser_error_t readAssetData(parser_context_t *ctx, masp_asset_data_t *asset) {
    if (ctx == NULL || asset == NULL) {
        return parser_unexpected_error;
    }

    asset->bytes.ptr = ctx->buffer + ctx->offset;
    CHECK_ERROR(readAddressAlt(ctx, &asset->token))
    CHECK_ERROR(readByte(ctx, &asset->denom))
    CHECK_ERROR(readByte(ctx, &asset->position))
    CHECK_ERROR(readByte(ctx, &asset->has_epoch))
    if (asset->has_epoch) {
        CHECK_ERROR(readUint64(ctx, &asset->epoch))
    }
    asset->bytes.len = ctx->buffer + ctx->offset - asset->bytes.ptr;
    return parser_ok;
}
