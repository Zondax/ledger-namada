/*******************************************************************************
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
********************************************************************************/
#pragma once

#include "parser_common.h"
#include <zxmacros.h>
#include "zxtypes.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PREFIX_IMPLICIT 0
#define PREFIX_ESTABLISHED 1
#define PREFIX_POS 2
#define PREFIX_SLASH_POOL 3
#define PREFIX_PARAMETERS 4
#define PREFIX_GOVERNANCE 5
#define PREFIX_IBC 6
#define PREFIX_ETH_BRIDGE 7
#define PREFIX_BRIDGE_POOL 8
#define PREFIX_MULTITOKEN 9
#define PREFIX_PGF 10
#define PREFIX_ERC20 11
#define PREFIX_NUT 12
#define PREFIX_IBC_TOKEN 13
#define PREFIX_MASP 14
#define PREFIX_TMP_STORAGE 15
#define PREFIX_INTERNAL 2

parser_error_t readAddressAlt(parser_context_t *ctx, AddressAlt *obj);
#ifdef __cplusplus
}
#endif
