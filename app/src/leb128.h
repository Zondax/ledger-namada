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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <zxerror.h>

#define MAX_LEB128_OUTPUT 10

zxerr_t encodeLEB128(uint64_t number, uint8_t *encoded, uint8_t encodedLen, uint8_t *encodedBytes);
// zxerr_t encodeSLEB128(const int64_t number, uint8_t *encoded, uint8_t encodedSize);

// zxerr_t decodeLEB128();
// zxerr_t decodeSLEB128();

#ifdef __cplusplus
}
#endif
