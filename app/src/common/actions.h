/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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
#pragma once

#include <stdint.h>
#include "crypto_helper.h"
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "zxerror.h"
#include "parser_txdef.h"
#include "zxformat.h"
#include "nvdata.h"

extern uint16_t cmdResponseLen;

__Z_INLINE zxerr_t app_fill_address(signing_key_type_e addressKind) {
    // Put data directly in the apdu buffer
    zemu_log("app_fill_address\n");
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    cmdResponseLen = 0;
    zxerr_t err = crypto_fillAddress(addressKind,
                                     G_io_apdu_buffer, IO_APDU_BUFFER_SIZE,
                                     &cmdResponseLen);

    if (err != zxerr_ok || cmdResponseLen == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return err;
}

__Z_INLINE zxerr_t app_fill_keys(key_kind_e requestedKey) {
    // Put data directly in the apdu buffer
    zemu_log("app_fill_keys\n");
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    cmdResponseLen = 0;
    zxerr_t err = crypto_fillMASP(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE,
                                     &cmdResponseLen, requestedKey);

    if (err != zxerr_ok || cmdResponseLen == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return err;
}

__Z_INLINE zxerr_t app_fill_randomness(masp_type_e type) {
    // Put data directly in the apdu buffer
    zemu_log("app_fill_randomness\n");
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    if (get_state() != STATE_INITIAL && get_state() != STATE_PROCESSED_RANDOMNESS) {
        return zxerr_unknown;
    }

    cmdResponseLen = 0;
    zxerr_t err = crypto_computeRandomness(type, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, &cmdResponseLen);

    if (err != zxerr_ok || cmdResponseLen == 0) {
        transaction_reset();
        THROW(APDU_CODE_DATA_INVALID);
    }

    set_state(STATE_PROCESSED_RANDOMNESS);
    return err;
}

__Z_INLINE zxerr_t app_fill_spend_sig() {
    // Put data directly in the apdu buffer
    zemu_log("app_fill_spend_sig\n");
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    cmdResponseLen = 0;
    zxerr_t err = crypto_extract_spend_signature(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, &cmdResponseLen);

    if (err != zxerr_ok || cmdResponseLen == 0) {
        transaction_reset();
        THROW(APDU_CODE_DATA_INVALID);
    }

    return err;
}

__Z_INLINE void app_sign() {
    const parser_tx_t *txObj = tx_get_txObject();

    const zxerr_t err = crypto_sign(txObj, G_io_apdu_buffer, sizeof(G_io_apdu_buffer) - 2);

    if (err != zxerr_ok) {
        transaction_reset();
        MEMZERO(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        transaction_reset();
        const uint16_t responseLen = PK_LEN_25519_PLUS_TAG + 2 * SALT_LEN + 2 * SIG_LEN_25519_PLUS_TAG + 2 + 10;
        set_code(G_io_apdu_buffer, responseLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, responseLen + 2);
    }
}

__Z_INLINE void app_sign_masp_spends() {
    parser_tx_t *txObj = tx_get_txObject();
    const zxerr_t err = crypto_sign_masp_spends(txObj, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3);

    if (err != zxerr_ok) {
        transaction_reset();
        MEMZERO(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, HASH_LEN, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, HASH_LEN + 2);
    }
}

__Z_INLINE void app_reject() {
    transaction_reset();
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_cmd() {
    set_code(G_io_apdu_buffer, cmdResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, cmdResponseLen + 2);
}

__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}
