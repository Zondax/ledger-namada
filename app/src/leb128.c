/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
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
 ******************************************************************************* */
#include "leb128.h"

zxerr_t encodeLEB128(uint64_t number, uint8_t *encoded, uint8_t encodedLen, uint8_t *encodedBytes) {
    if (encoded == NULL || encodedBytes == NULL) {
        return zxerr_encoding_failed;
    }

    *encodedBytes = 0;
    do {
        uint8_t byte = number & 0x7F;
        number >>= 7;
        if (number) {
            byte |= 0x80;
        }
        encoded[(*encodedBytes)++] = byte;
    } while (number);

    return zxerr_ok;
}
