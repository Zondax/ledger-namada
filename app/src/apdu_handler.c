/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*   (c) 2016 Ledger
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

#include "app_main.h"

#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>
#include <ux.h>

#include "view.h"
#include "view_internal.h"
#include "actions.h"
#include "tx.h"
#include "addr.h"
#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"
#include "view_internal.h"
#include "review_keys.h"

static bool tx_initialized = false;

__Z_INLINE void extractHDPath(uint32_t rx, uint32_t offset) {
    ZEMU_LOGF(50, "Extract HDPath\n")
    tx_initialized = false;

    const uint8_t pathLength = G_io_apdu_buffer[offset];
    offset++;

    if (pathLength != HDPATH_LEN_DEFAULT || (rx - offset) != sizeof(uint32_t) * pathLength) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    memcpy(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_DEFAULT;

    const bool testnet = hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];
    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            tx_initialized = false;
            return true;
    }

    THROW(APDU_CODE_INVALIDP1P2);
}

__Z_INLINE void handleSignTransaction(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    ZEMU_LOGF(50, "handleSignTransaction\n")
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    CHECK_APP_CANARY()

    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        transaction_reset();
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    transaction_reset();
    *flags |= IO_ASYNCH_REPLY;
}

// For wrapper transactions, address is derived from Ed25519 pubkey
__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleGetAddr\n");
    extractHDPath(rx, OFFSET_DATA);
    *tx = 0;
    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zxerr_t zxerr = app_fill_address(key_ed25519);
    if(zxerr != zxerr_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_cmd);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = cmdResponseLen;
    THROW(APDU_CODE_OK);
}
#if defined(COMPILE_MASP)
__Z_INLINE void handleSignMaspSpends(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    ZEMU_LOGF(50, "handleSignMaspSpends\n")
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    CHECK_APP_CANARY()

    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        transaction_reset();
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_masp_spends);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetKeys(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);
    if (G_io_apdu_buffer[OFFSET_P2] >= InvalidKey) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    const key_kind_e requestedKeys = (key_kind_e) G_io_apdu_buffer[OFFSET_P2];

    // ViewKey will require explicit user confirmation to leave the device
    if (!requireConfirmation && requestedKeys == ViewKeys) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    zxerr_t zxerr = app_fill_keys(requestedKeys);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    if (requireConfirmation) {
        review_keys_menu(requestedKeys);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = cmdResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleComputeMaspRand(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx, __Z_UNUSED uint32_t rx, masp_type_e type) {
    *tx = 0;
    zxerr_t zxerr = app_fill_randomness(type);
    if (zxerr != zxerr_ok) {
        transaction_reset();
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    *tx = cmdResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleExtractSpendSign(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx, __Z_UNUSED uint32_t rx) {
    *tx = 0;
    zxerr_t zxerr = app_fill_spend_sig();
    
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    *tx = cmdResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleCleanRandomnessBuffers(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx, __Z_UNUSED uint32_t rx) {
    *tx = 0;
    transaction_reset();
    THROW(APDU_CODE_OK);
}

#endif

__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx)
{
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (LEDGER_MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (LEDGER_MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (LEDGER_MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (LEDGER_MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (LEDGER_PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (LEDGER_PATCH_VERSION >> 0) & 0xFF;

    // SDK won't reply if device is blocked ---> Always false
    G_io_apdu_buffer[7] = 0;

    G_io_apdu_buffer[8] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[9] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[10] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[11] = (TARGET_ID >> 0) & 0xFF;

    *tx += 12;
    THROW(APDU_CODE_OK);
}

#if defined(APP_TESTING)
void handleTest(__Z_UNUSED volatile uint32_t *flags, __Z_UNUSED volatile uint32_t *tx, __Z_UNUSED uint32_t rx) {
    THROW(APDU_CODE_OK);
}
#endif

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx);
                    break;
                }

                case INS_GET_ADDR: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx);
                    break;
                }

                case INS_SIGN: {
                    CHECK_PIN_VALIDATED()
                    handleSignTransaction(flags, tx, rx);
                    break;
                }
#if defined(COMPILE_MASP)
                case INS_GET_KEYS: {
                    CHECK_PIN_VALIDATED()
                    handleGetKeys(flags, tx, rx);
                    break;
                }

                case INS_GET_SPEND_RAND: {
                    CHECK_PIN_VALIDATED()
                    handleComputeMaspRand(flags, tx, rx, spend);
                    break;
                }

                case INS_GET_OUTPUT_RAND: {
                    CHECK_PIN_VALIDATED()
                    handleComputeMaspRand(flags, tx, rx, output);
                    break;
                }

                case INS_GET_CONVERT_RAND: {
                    CHECK_PIN_VALIDATED()
                    handleComputeMaspRand(flags, tx, rx, convert);
                    break;
                }

                case INS_SIGN_MASP_SPENDS: {
                    CHECK_PIN_VALIDATED()
                    handleSignMaspSpends(flags, tx, rx);
                    break;
                }

                case INS_EXTRACT_SPEND_SIGN: {
                    CHECK_PIN_VALIDATED()
                    handleExtractSpendSign(flags, tx, rx);
                    break;
                }
                case INS_CLEAN_BUFFERS: {
                    CHECK_PIN_VALIDATED()
                    handleCleanRandomnessBuffers(flags, tx, rx);
                    break;
                }
#endif
#if defined(APP_TESTING)
                case INS_TEST: {
                    handleTest(flags, tx, rx);
                    THROW(APDU_CODE_OK);
                    break;
                }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY
        {
        }
    }
    END_TRY;
}
