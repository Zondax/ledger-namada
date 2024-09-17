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
export const CLA = 0x57
export const INS = {
  GET_VERSION: 0x00,
  GET_TRANSPARENT_ADDRESS: 0x01,
  SIGN: 0x02,

  GET_KEYS: 0x03,
  GET_SPEND_RAND: 0x04,
  GET_OUTPUT_RAND: 0x05,
  GET_CONVERT_RAND: 0x06,
  SIGN_MASP_SPENDS: 0x07,
  EXTRACT_SPEND_SIGN: 0x08,
}
export const SALT_LEN = 8
export const HASH_LEN = 32
export const PK_LEN_PLUS_TAG = 33
export const SIG_LEN_PLUS_TAG = 65
export const KEY_LENGTH = 32
export const RANDOMNESS_LENGTH = 32
