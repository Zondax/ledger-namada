/*******************************************************************************
 *   (c) 2018 -2 024 Zondax AG
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
#include "tx_hash.h"
#include "cx.h"
#include "cx.h"
#include <zxformat.h>
#include <zxmacros.h>
#include "parser_txdef.h"
#include "parser_impl_masp.h"

// Hash MaspTx Header information
zxerr_t tx_hash_header_data(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_HEADERS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    masp_tx_data_t *maspTx = (masp_tx_data_t *)&txObj->transaction.sections.maspTx.data;
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, (const uint8_t *)&maspTx->tx_version, 4, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, (const uint8_t *)&maspTx->version_group_id, 4, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, (const uint8_t *)&maspTx->consensus_branch_id, 4, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, (const uint8_t *)&maspTx->lock_time, 4, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, (const uint8_t *)&maspTx->expiry_height, 4, output, HASH_SIZE));

    return zxerr_ok;
}

/// Sequentially append the transparent inputs
/// to a hash personalized by ZCASH_INPUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
zxerr_t tx_hash_transparent_inputs(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_INPUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if(txObj->transaction.sections.maspTx.data.transparent_bundle.n_vin == 0){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    const uint8_t *vin = txObj->transaction.sections.maspTx.data.transparent_bundle.vin.ptr;

    for(uint64_t i = 0; i < txObj->transaction.sections.maspTx.data.transparent_bundle.n_vin; i++, vin += VIN_LEN){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, vin, ASSET_ID_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, vin + VIN_VALUE_OFFSET, sizeof(uint64_t), NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, vin + VIN_ADDR_OFFSET, IMPLICIT_ADDR_LEN, NULL, 0));
    }
    CHECK_CX_OK(cx_hash_final(&ctx.header, output));

    return zxerr_ok;

}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
zxerr_t tx_hash_transparent_outputs(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_OUTPUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if(txObj->transaction.sections.maspTx.data.transparent_bundle.n_vout == 0){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    const uint8_t *vout = txObj->transaction.sections.maspTx.data.transparent_bundle.vout.ptr;

    for(uint64_t i = 0; i < txObj->transaction.sections.maspTx.data.transparent_bundle.n_vout; i++, vout += VOUT_LEN){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, vout, VOUT_LEN, NULL, 0));
    }

    CHECK_CX_OK(cx_hash_final(&ctx.header, output));

    return zxerr_ok;

}

/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk)*\] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
zxerr_t tx_hash_sapling_spends(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if(txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends == 0){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    cx_blake2b_t nullifier_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&nullifier_ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    cx_blake2b_t nc_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&nc_ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    const uint8_t *spend = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_spends.ptr;
    const uint64_t n_shielded_spends = txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends;
    const uint8_t *spend_anchor_ptr = txObj->transaction.sections.maspTx.data.sapling_bundle.anchor_shielded_spends.ptr;

    for (uint64_t i = 0; i < n_shielded_spends; i++, spend += SHIELDED_SPENDS_LEN) {
        shielded_spends_t *shielded_spends = (shielded_spends_t *)spend;

        CHECK_CX_OK(cx_hash_no_throw(&nullifier_ctx.header, 0, shielded_spends->nullifier, NULLIFIER_LEN, NULL, 0));

        CHECK_CX_OK(cx_hash_no_throw(&nc_ctx.header, 0, shielded_spends->cv, CV_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nc_ctx.header, 0, spend_anchor_ptr, ANCHOR_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nc_ctx.header, 0, shielded_spends->rk, RK_LEN, NULL, 0));
    }

    uint8_t nullifier_hash[HASH_SIZE] = {0};
    uint8_t nc_hash[HASH_SIZE] = {0};

    CHECK_CX_OK(cx_hash_final(&nullifier_ctx.header, nullifier_hash));
    CHECK_CX_OK(cx_hash_final(&nc_ctx.header, nc_hash));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, nullifier_hash, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, nc_hash, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

/// Write disjoint parts of each MASP shielded convert to a hash:
/// * \[(cv, anchor)*\] - personalized with ZCASH_SAPLING_CONVERTS_HASH_PERSONALIZATION
///
zxerr_t tx_hash_sapling_converts(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_CONVERTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if(txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_converts == 0){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    const uint8_t *spend = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_converts.ptr;

    for(uint64_t i = 0; i < txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_converts; i++, spend += SHIELDED_CONVERTS_LEN){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, spend, CV_LEN, NULL,0));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, txObj->transaction.sections.maspTx.data.sapling_bundle.anchor_shielded_converts.ptr, ANCHOR_LEN, NULL, 0));
    }

    CHECK_CX_OK(cx_hash_final(&ctx.header, output));

    return zxerr_ok;
}

/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext)*\] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
zxerr_t tx_hash_sapling_outputs(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if(txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_outputs == 0){
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    cx_blake2b_t compact_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&compact_ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    cx_blake2b_t memo_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&memo_ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    cx_blake2b_t non_compact_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&non_compact_ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    const uint8_t *shielded_outputs_ptr = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_outputs.ptr;
    const uint64_t n_shielded_outputs = txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_outputs;

    for (uint64_t i = 0; i < n_shielded_outputs; i++, shielded_outputs_ptr += SHIELDED_OUTPUTS_LEN) {
        const shielded_outputs_t *shielded_output = (const shielded_outputs_t *)shielded_outputs_ptr;

        CHECK_CX_OK(cx_hash_no_throw(&compact_ctx.header, 0, shielded_output->cmu, CMU_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&compact_ctx.header, 0, shielded_output->ephemeral_key, EPK_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&compact_ctx.header, 0, shielded_output->enc_ciphertext, COMPACT_NOTE_SIZE, NULL, 0));

        CHECK_CX_OK(cx_hash_no_throw(&memo_ctx.header, 0, shielded_output->enc_ciphertext + COMPACT_NOTE_SIZE, NOTE_PLAINTEXT_SIZE, NULL, 0));

        CHECK_CX_OK(cx_hash_no_throw(&non_compact_ctx.header, 0, shielded_output->cv, CV_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&non_compact_ctx.header, 0, shielded_output->enc_ciphertext + COMPACT_NOTE_SIZE + NOTE_PLAINTEXT_SIZE, ENC_CIPHER_LEN - COMPACT_NOTE_SIZE - NOTE_PLAINTEXT_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&non_compact_ctx.header, 0, shielded_output->out_ciphertext, OUT_CIPHER_LEN, NULL, 0));
    }

    uint8_t compact_hash[HASH_SIZE] = {0};
    uint8_t memo_hash[HASH_SIZE] = {0};
    uint8_t non_compact_hash[HASH_SIZE] = {0};

    CHECK_CX_OK(cx_hash_final(&compact_ctx.header, compact_hash));
    CHECK_CX_OK(cx_hash_final(&memo_ctx.header, memo_hash));
    CHECK_CX_OK(cx_hash_final(&non_compact_ctx.header, non_compact_hash));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, compact_hash, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, memo_hash, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, non_compact_hash, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

zxerr_t tx_hash_sapling_data(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_SAPLING_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    uint8_t spends_hash[32] = {0};
    uint8_t converts_hash[32] = {0};
    uint8_t outputs_hash[32] = {0};

    if (txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends != 0 || 
        txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_converts != 0 || 
        txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_outputs != 0) {
        CHECK_ZXERR(tx_hash_sapling_spends(txObj, spends_hash));

        // TODO: there is not an example to validate converts
        CHECK_ZXERR(tx_hash_sapling_converts(txObj, converts_hash));

        CHECK_ZXERR(tx_hash_sapling_outputs(txObj, outputs_hash));

        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, spends_hash, HASH_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, converts_hash, HASH_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, outputs_hash, HASH_SIZE, NULL, 0));

        if (txObj->transaction.sections.maspTx.data.sapling_bundle.n_value_sum_asset_type == 0) {
            uint8_t zero_byte = 0;
            CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, &zero_byte, 1, NULL, 0));
        } else {
            // TODO: while debugging
            // https://github.com/anoma/masp/blob/8d83b172698098fba393006016072bc201ed9ab7/masp_primitives/src/transaction/txid.rs#L234,
            // there is a 0x01 byte at the beginning. Is this byte representing the n_value_sum_asset_type?
            uint8_t asset_type = (uint8_t)txObj->transaction.sections.maspTx.data.sapling_bundle.n_value_sum_asset_type;
            CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, &asset_type, 1, NULL, 0));

            CHECK_CX_OK(cx_hash_no_throw(
                &ctx.header, 0, txObj->transaction.sections.maspTx.data.sapling_bundle.value_sum_asset_type.ptr,
                (ASSET_ID_LEN + INT_128_LEN) * txObj->transaction.sections.maspTx.data.sapling_bundle.n_value_sum_asset_type,
                NULL, 0));
        }
    }

    CHECK_CX_OK(cx_hash_final(&ctx.header, output));

    return zxerr_ok;
}

zxerr_t tx_hash_transparent_data(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_TRANSPARENT_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    uint8_t outputs_hash[32] = {0};
    uint8_t inputs_hash[32] = {0};

    if (txObj->transaction.sections.maspTx.data.transparent_bundle.n_vin > 0 ||
        txObj->transaction.sections.maspTx.data.transparent_bundle.n_vout > 0) {
        CHECK_ZXERR(tx_hash_transparent_inputs(txObj, inputs_hash));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, inputs_hash, HASH_SIZE, NULL, 0));

        CHECK_ZXERR(tx_hash_transparent_outputs(txObj, outputs_hash));
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, outputs_hash, HASH_SIZE, NULL, 0));
    }

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, NULL, 0, output, HASH_SIZE));
    return zxerr_ok;
}

zxerr_t tx_hash_txId(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    uint8_t personal[16] = {0};
    MEMCPY(personal, ZCASH_TX_PERSONALIZATION_PREFIX, 12);
    
    // Use BRANCH_ID_IDENTIFIER to set the last 4 bytes
    uint32_t branch_id = BRANCH_ID_IDENTIFIER;
    memcpy(&personal[12], &branch_id, sizeof(branch_id));

    cx_blake2b_t ctx_hash = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx_hash, 256, NULL, 0, personal, PERSONALIZATION_SIZE));

    uint8_t header[32] = {0};
    uint8_t transparent[32] = {0};
    uint8_t sapling[32] = {0};

    CHECK_ZXERR(tx_hash_header_data(txObj, header));
    CHECK_ZXERR(tx_hash_transparent_data(txObj, transparent));
    CHECK_ZXERR(tx_hash_sapling_data(txObj, sapling));

    CHECK_CX_OK(cx_hash_no_throw(&ctx_hash.header, 0, header, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx_hash.header, 0, transparent, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx_hash.header, CX_LAST, sapling, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}
