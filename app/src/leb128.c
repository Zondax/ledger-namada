/** ******************************************************************************
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
 ******************************************************************************* */
#include "leb128.h"
#include <stddef.h>

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
        if (*encodedBytes >= encodedLen) return zxerr_buffer_too_small;
        encoded[(*encodedBytes)++] = byte;
    } while (number);

    return zxerr_ok;
}

zxerr_t decodeLEB128(const uint8_t *input, uint16_t inputSize, uint8_t *consumed, uint64_t *v) {
    uint16_t  i = 0;

    *v = 0;
    uint16_t shift = 0;
    while (i < 10u && i < inputSize) {
        uint64_t b = input[i] & 0x7fu;

        if (shift >= 63 && b > 1) {
            // This will overflow uint64_t
            break;
        }

        *v |= b << shift;

        if (!(input[i] & 0x80u)) {
            *consumed = i + 1;
            return zxerr_ok;
        }

        shift += 7;
        i++;
    }

    // exit because of overflowing outputSize
    *v = 0;
    return zxerr_unknown;
}
