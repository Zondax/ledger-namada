/*******************************************************************************
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
********************************************************************************/
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t seconds;
    uint32_t nanos;
} prototimestamp_t;
typedef struct {
    const uint8_t *code;
    uint32_t codeSize;

    const uint8_t *data;
    uint32_t dataSize;

    prototimestamp_t timestamp;
} outer_layer_tx_t;

typedef struct{
    outer_layer_tx_t outerTxn;
} parser_tx_t;


#ifdef __cplusplus
}
#endif
