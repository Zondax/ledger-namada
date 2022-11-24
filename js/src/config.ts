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
export const CLA = 0x80;
export const INS = {
  GET_VERSION: 0x00,
  GET_PUBLIC_KEY: 0x01,
  SIGN_MSGPACK: 0x02,
  GET_MASP_ADDRESS: 0x03,
  GET_IVK : 0x04,
  GET_OVK:  0x05,
  GET_NF: 0x06,
};
export const PK_LEN_25519 = 32;
export const HASH_LEN_SHA256 = 32;
