/*******************************************************************************
 *   (c) 2018 -2022 Zondax AG
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

    for(uint64_t i = 0; i < txObj->transaction.sections.maspTx.data.transparent_bundle.n_vin; i++, vin += VOUT_LEN){
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

    for(uint64_t i = 0; i < txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_spends; i++, spend += SHIELDED_SPENDS_LEN){
        CHECK_CX_OK(cx_hash_no_throw(&nullifier_ctx.header, 0, spend + CV_LEN, NULLIFIER_LEN, NULL,0));

        CHECK_CX_OK(cx_hash_no_throw(&nc_ctx.header, 0, spend, CV_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nc_ctx.header, 0, txObj->transaction.sections.maspTx.data.sapling_bundle.anchor_shielded_spends.ptr, ANCHOR_LEN, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nc_ctx.header, 0, spend + CV_LEN + NULLIFIER_LEN, RK_LEN, NULL, 0));
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

    const uint8_t *out = txObj->transaction.sections.maspTx.data.sapling_bundle.shielded_outputs.ptr;

    for (uint64_t i = 0; i < txObj->transaction.sections.maspTx.data.sapling_bundle.n_shielded_outputs; i++, out += SHIELDED_OUTPUTS_LEN) {
        CHECK_CX_OK(cx_hash_no_throw(&compact_ctx.header, 0, out + CMU_OFFSET, CMU_LEN, NULL,0));
        CHECK_CX_OK(cx_hash_no_throw(&compact_ctx.header, 0, out + EPK_OFFSET, EPK_OFFSET, NULL,0));
        CHECK_CX_OK(cx_hash_no_throw(&compact_ctx.header, 0, out + ENC_CIPHER_OFFSET, COMPACT_NOTE_SIZE, NULL,0));

        CHECK_CX_OK(cx_hash_no_throw(&memo_ctx.header, 0,out + ENC_CIPHER_OFFSET + COMPACT_NOTE_SIZE, NOTE_PLAINTEXT_SIZE, NULL,0));

        CHECK_CX_OK(cx_hash_no_throw(&non_compact_ctx.header, 0, out, CV_LEN, NULL,0));
        CHECK_CX_OK(cx_hash_no_throw(&non_compact_ctx.header, 0, out + ENC_CIPHER_OFFSET + COMPACT_NOTE_SIZE + NOTE_PLAINTEXT_SIZE ,
                    ENC_CIPHER_LEN - (COMPACT_NOTE_SIZE + NOTE_PLAINTEXT_SIZE), NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&non_compact_ctx.header, 0, out + OUT_CIPHER_OFFSET, OUT_CIPHER_LEN, NULL,0));

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
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    uint8_t spends_hash[32] = {0};
    uint8_t converts_hash[32] = {0};
    uint8_t outputs_hash[32] = {0};

    CHECK_ZXERR(tx_hash_transparent_inputs(txObj, spends_hash));
    CHECK_ZXERR(tx_hash_transparent_outputs(txObj, converts_hash));
    CHECK_ZXERR(tx_hash_transparent_outputs(txObj, outputs_hash));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, spends_hash, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, converts_hash, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, outputs_hash, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

zxerr_t tx_hash_transparent_data(const parser_tx_t *txObj, uint8_t *output) {
    if (txObj == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t*)ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    uint8_t outputs_hash[32] = {0};
    uint8_t inputs_hash[32] = {0};

    CHECK_ZXERR(tx_hash_transparent_inputs(txObj, inputs_hash));
    CHECK_ZXERR(tx_hash_transparent_outputs(txObj, outputs_hash));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, inputs_hash, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, outputs_hash, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}
