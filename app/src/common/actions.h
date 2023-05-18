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
#pragma once

#include <stdint.h>
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "zxerror.h"
#include "parser_txdef.h"
#include "zxformat.h"

typedef struct {
    address_kind_e kind;
    uint16_t len;
} address_state_t;

typedef struct {
    key_type_e kind;
    uint16_t len;
} key_state_t;

extern address_state_t action_addrResponse;
extern key_state_t key_state;

__Z_INLINE zxerr_t app_fill_address(signing_key_type_e addressKind) {
    // Put data directly in the apdu buffer
    zemu_log("app_fill_address\n");
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    action_addrResponse.len = 0;
    zxerr_t err = crypto_fillAddress(addressKind,
                                     G_io_apdu_buffer, IO_APDU_BUFFER_SIZE,
                                     &action_addrResponse.len);

    if (err != zxerr_ok || action_addrResponse.len == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return err;
}

__Z_INLINE void app_sign() {
    const parser_tx_t *txObj = tx_get_txObject();

    uint8_t pubkey[PK_LEN_25519] = {0};
    const bytes_t pubkey_bytes = {.ptr = pubkey, .len = PK_LEN_25519};
    zxerr_t err = crypto_extractPublicKey_ed25519(pubkey, sizeof(pubkey));
    if (err == zxerr_ok) {
        const zxerr_t headerSigErr = crypto_signHeader(&txObj->transaction.header, &pubkey_bytes);
        const zxerr_t dataSigErr = crypto_signDataSection(&txObj->transaction.sections.data, &pubkey_bytes);
        const zxerr_t codeSigErr = crypto_signCodeSection(&txObj->transaction.sections.code, &pubkey_bytes);
        err = (headerSigErr == zxerr_ok && dataSigErr == zxerr_ok && codeSigErr == zxerr_ok) ? zxerr_ok : zxerr_unknown;
    }

    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    }
}

__Z_INLINE void app_reject() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, action_addrResponse.len, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponse.len + 2);
}

__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}
