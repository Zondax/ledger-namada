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
import { KEY_LENGTH, PK_LEN_PLUS_TAG, RANDOMNESS_LENGTH, SALT_LEN, SIG_LEN_PLUS_TAG } from './config'
import { ISignature, KeyResponse, NamadaKeys, ResponseGetConvertRandomness, ResponseGetOutputRandomness, ResponseGetSpendRandomness, ResponseSignMasp, ResponseSpendSign } from './types'

export function getSignatureResponse(response: Buffer): ISignature {
  // App sign response: [ rawPubkey(33) | raw_salt(8) | raw_signature(65) | wrapper_salt(8) | wrapper_signature(65) |
  // raw_indices_len(1) | wrapper_indices_len(1) | indices(wrapper_indices_len) ]

  let offset = 0
  const rawPubkey = Buffer.from(response.subarray(offset, offset + PK_LEN_PLUS_TAG))

  offset += PK_LEN_PLUS_TAG
  const raw_salt = Buffer.from(response.subarray(offset, offset + SALT_LEN))
  offset += SALT_LEN
  const raw_signature = Buffer.from(response.subarray(offset, offset + SIG_LEN_PLUS_TAG))

  offset += SIG_LEN_PLUS_TAG
  const wrapper_salt = Buffer.from(response.subarray(offset, offset + SALT_LEN))
  offset += SALT_LEN
  const wrapper_signature = Buffer.from(response.subarray(offset, offset + SIG_LEN_PLUS_TAG))

  offset += SIG_LEN_PLUS_TAG
  const raw_indices_len = response[offset]
  offset += 1
  const raw_indices = Buffer.from(response.subarray(offset, offset + raw_indices_len))
  offset += raw_indices_len

  const wrapper_indices_len = response[offset]
  offset += 1
  const wrapper_indices = Buffer.from(response.subarray(offset, offset + wrapper_indices_len))
  offset += wrapper_indices_len

  return {
    rawPubkey,
    raw_salt,
    raw_signature,
    wrapper_salt,
    wrapper_signature,
    raw_indices,
    wrapper_indices,
  }
}

export function processGetAddrResponse(response: Buffer) {
  const errorCodeData = response.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  const rawPubkey = response.subarray(0, PK_LEN_PLUS_TAG)
  response = response.subarray(PK_LEN_PLUS_TAG)

  const pubkeyLen = response[0]
  const pubkey = response.subarray(1, pubkeyLen + 1)
  response = response.subarray(pubkeyLen + 1)

  const addressLen = response[0]
  const address = response.subarray(1, addressLen + 1)

  console.log(pubkey.toString())
  console.log(address.toString())

  return {
    rawPubkey,
    pubkey,
    address,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export function processGetKeysResponse(response: Buffer, keyType: NamadaKeys): KeyResponse {
  const errorCodeData = response.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  let requestedKey: KeyResponse = {
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  }

  switch (keyType) {
    case NamadaKeys.PublicAddress: {
      const publicAddress = Buffer.from(response.subarray(0, KEY_LENGTH))
      requestedKey = {
        ...requestedKey,
        publicAddress,
      }
      break
    }

    case NamadaKeys.ViewKey: {
      const viewKey = Buffer.from(response.subarray(0, 2 * KEY_LENGTH))
      response = response.subarray(2 * KEY_LENGTH)

      const ovk = Buffer.from(response.subarray(0, KEY_LENGTH))
      response = response.subarray(KEY_LENGTH)

      const ivk = Buffer.from(response.subarray(0, KEY_LENGTH))
      response = response.subarray(KEY_LENGTH)

      requestedKey = {
        ...requestedKey,
        viewKey,
        ovk,
        ivk,
      }
      break
    }

    case NamadaKeys.ProofGenerationKey: {
      const ak = Buffer.from(response.subarray(0, KEY_LENGTH))
      response = response.subarray(KEY_LENGTH)

      const nsk = Buffer.from(response.subarray(0, KEY_LENGTH))
      response = response.subarray(KEY_LENGTH)

      requestedKey = {
        ...requestedKey,
        ak,
        nsk,
      }
      break
    }
  }

  return requestedKey
}

export function processSpendRandomnessResponse(
  response: Buffer,
): ResponseGetSpendRandomness {
  const errorCodeData = response.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  return {
    rcv: Buffer.from(response.subarray(0, RANDOMNESS_LENGTH)),
    alpha: Buffer.from(response.subarray(RANDOMNESS_LENGTH, 2 * RANDOMNESS_LENGTH)),
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export function processOutputRandomnessResponse(
  response: Buffer,
): ResponseGetOutputRandomness {
  const errorCodeData = response.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  return {
    rcv: Buffer.from(response.subarray(0, RANDOMNESS_LENGTH)),
    rcm: Buffer.from(response.subarray(RANDOMNESS_LENGTH, 2 * RANDOMNESS_LENGTH)),
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export function processConvertRandomnessResponse(
  response: Buffer,
): ResponseGetConvertRandomness {
  const errorCodeData = response.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  return {
    rcv: Buffer.from(response.subarray(0, RANDOMNESS_LENGTH)),
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export function processMaspSign(
  response: Buffer,
): ResponseSignMasp {
  const errorCodeData = response.subarray(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
  let hash = Buffer.from(response.subarray(0, 32))
  
  return {
    hash,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export function processSpendSignResponse(response: Buffer): ResponseSpendSign {
  const errorCodeData = response.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  return {
    rbar: Buffer.from(response.subarray(0, 32)),
    sbar: Buffer.from(response.subarray(32, 64)),
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}
