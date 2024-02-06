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

#ifdef __cplusplus
extern "C" {
#endif

#include "parser_txdef.h"
#include "parser_common.h"

#include <stdint.h>

parser_error_t readBecomeValidator(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v);
parser_error_t readUnjailValidator(const bytes_t *data, parser_tx_t *v);
parser_error_t readActivateValidator(const bytes_t *data, tx_activate_validator_t *txObject);



#ifdef __cplusplus
}
#endif
