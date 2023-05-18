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

import { errorCodeToString } from './common'
import { HASH_LEN, PK_LEN_25519, SALT_LEN } from './config'
import { ISignature } from './types'

export function processGetSignatureResponse(response: Buffer): ISignature {
  console.log('Processing get signature response')

  const salt = Buffer.from(response.subarray(0, SALT_LEN))
  const hash = Buffer.from(response.subarray(SALT_LEN, SALT_LEN + HASH_LEN))
  const pubkey = Buffer.from(response.subarray(SALT_LEN + HASH_LEN, SALT_LEN + HASH_LEN + PK_LEN_25519))
  const signature = Buffer.from(response.subarray(SALT_LEN + HASH_LEN + PK_LEN_25519, -2))

  return {
    salt,
    hash,
    pubkey,
    signature,
  }
}

export function processGetAddrResponse(response: Buffer) {
  console.log('Processing get address response')

  let partialResponse = response

  const errorCodeData = partialResponse.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const publicKey = Buffer.from(partialResponse.slice(0, PK_LEN_25519))

  //"advance" buffer
  partialResponse = partialResponse.slice(PK_LEN_25519)

  // get the implicit address corresponding to the public key
  const address = Buffer.from(partialResponse.slice(0, -2))

  return {
    publicKey,
    address,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

// Not used yet
// function processGetShieldedAddrResponse(response: Buffer) {
//   console.log("Processing get address response")

//   let partialResponse = response

//   const errorCodeData = partialResponse.slice(-2)
//   const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

//   //get public key len (variable)
//   const raw_pkd = Buffer.from(partialResponse.slice(0, 32))

//   //"advance" buffer
//   partialResponse = partialResponse.slice(32)

//   // get the length of the bech32m address
//   const bech32m_len = partialResponse[0]

//   //"advance" buffer
//   partialResponse = partialResponse.slice(1)

//   // get the bech32m encoding of the shielded address
//   const bech32m_addr = Buffer.from(partialResponse.slice(0, bech32m_len))

//   return {
//     raw_pkd,
//     bech32m_len,
//     bech32m_addr,
//     returnCode,
//     errorMessage: errorCodeToString(returnCode),
//   }
// }

// function processIncomingViewingKeyResponse(response: Buffer) {
//   console.log("Processing get IVK response")

//   const partialResponse = response

//   const errorCodeData = partialResponse.slice(-2)
//   const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

//   //get public key len (variable)
//   const raw_ivk = Buffer.from(partialResponse.slice(0, 32))

//   return {
//     raw_ivk,
//     returnCode,
//     errorMessage: errorCodeToString(returnCode),
//   }
// }

// function processNullifierResponse(response: Buffer) {
//   console.log("Processing get nullifier response")

//   const partialResponse = response

//   const errorCodeData = partialResponse.slice(-2)
//   const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

//   const raw_nf = Buffer.from(partialResponse.slice(0, 32))

//   return {
//     raw_nf,
//     returnCode,
//     errorMessage: errorCodeToString(returnCode),
//   }
// }

// function processOutgoingViewingKeyResponse(response: Buffer) {
//   console.log("Processing get OVK response")

//   const partialResponse = response

//   const errorCodeData = partialResponse.slice(-2)
//   const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

//   //get public key len (variable)
//   const raw_ovk = Buffer.from(partialResponse.slice(0, 32))

//   return {
//     raw_ovk,
//     returnCode,
//     errorMessage: errorCodeToString(returnCode),
//   }
// }
