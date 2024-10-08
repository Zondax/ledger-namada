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

#include <stdio.h>

#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"
#include "keys_def.h"
#include "os.h"

#include "view.h"
#include "actions.h"
#include "review_keys.h"

zxerr_t getNumItemsPublicAddress(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [public address | path]
    *num_items = 2;
    return zxerr_ok;
}

zxerr_t getItemPublicAddress(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    ZEMU_LOGF(50, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Address");
            const char* address = (const char*)G_io_apdu_buffer;
            pageStringHex(outVal, outValLen, address, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 1: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[200] = {0};
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t getNumItemsProofGenerationKey(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [ak | nsk | HD path]
    *num_items = 3;
    return zxerr_ok;
}

zxerr_t getItemProofGenerationKey(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    ZEMU_LOGF(50, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "AuthKey");
            const char* ak = (const char*)G_io_apdu_buffer;
            pageStringHex(outVal, outValLen, ak, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 1:
            snprintf(outKey, outKeyLen, "ProofAuthKey");
            const char* nsk = (const char*)G_io_apdu_buffer + KEY_LENGTH;
            pageStringHex(outVal, outValLen, nsk, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 2: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[200] = {0};
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t getNumItemsViewKey(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [viewKey | ivk | ovk | dk | HD path]
    *num_items = 5;
    return zxerr_ok;
}

zxerr_t getItemViewKey(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    ZEMU_LOGF(50, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)

    const KeyData* keyData = (const KeyData*)G_io_apdu_buffer;
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "ViewKey");
            pageStringHex(outVal, outValLen, keyData->viewKey, 2 * KEY_LENGTH, pageIdx, pageCount);
            break;
        case 1:
            snprintf(outKey, outKeyLen, "IVK");
            pageStringHex(outVal, outValLen, keyData->ivk, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "OVK");
            pageStringHex(outVal, outValLen, keyData->ovk, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 3:
            snprintf(outKey, outKeyLen, "DK");
            pageStringHex(outVal, outValLen, keyData->dk, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 4: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[200] = {0};
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

void review_keys_menu(key_kind_e keyType) {
    const review_type_e reviewType = keyType == PublicAddress ? REVIEW_ADDRESS : REVIEW_TXN;

    void *getItemFunction = NULL;
    void *getNumItemFunction = NULL;

    switch (keyType) {
        case PublicAddress:
            getItemFunction = getItemPublicAddress;
            getNumItemFunction = getNumItemsPublicAddress;
            break;
        case ViewKeys:
            getItemFunction = getItemViewKey;
            getNumItemFunction = getNumItemsViewKey;
            break;
        case ProofGenerationKey:
            getItemFunction = getItemProofGenerationKey;
            getNumItemFunction = getNumItemsProofGenerationKey;
            break;

        default:
            break;
    }

    view_review_init(getItemFunction, getNumItemFunction, app_reply_cmd);
    view_review_show(reviewType);
}
