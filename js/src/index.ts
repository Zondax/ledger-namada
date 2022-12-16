/** ******************************************************************************
 *  (c) 2019-2020 Zondax GmbH
 *  (c) 2016-2017 Ledger
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
import Transport from '@ledgerhq/hw-transport'
import {
  ResponseAddress,
  ResponseAppInfo,
  ResponseIncomingViewingKey,
  ResponseNullifier,
  ResponseOutgoingViewingKey,
  ResponseShieldedAddress,
  ResponseSign,
  ResponseVersion
} from './types'
import {
  CHUNK_SIZE,
  errorCodeToString,
  getVersion,
  LedgerError,
  P1_VALUES,
  P2_VALUES,
  PAYLOAD_TYPE,
  processErrorResponse,
  serializePath,
} from './common'

import {CLA, INS, PK_LEN_25519} from "./config";


export { LedgerError }
export * from './types'

function processGetAddrResponse(response: Buffer) {
  console.log("Processing get address response")

  let partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const publicKey = Buffer.from(partialResponse.slice(0,PK_LEN_25519))

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

function processGetShieldedAddrResponse(response: Buffer) {
  console.log("Processing get address response")

  let partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const raw_pkd = Buffer.from(partialResponse.slice(0, 32))

  //"advance" buffer
  partialResponse = partialResponse.slice(32)

  // get the length of the bech32m address
  const bech32m_len = partialResponse[0]

  //"advance" buffer
  partialResponse = partialResponse.slice(1)

  // get the bech32m encoding of the shielded address
  const bech32m_addr = Buffer.from(partialResponse.slice(0, bech32m_len))


  return {
    raw_pkd,
    bech32m_len,
    bech32m_addr,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}


function processIncomingViewingKeyResponse(response: Buffer) {
  console.log("Processing get IVK response")

  const partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const raw_ivk = Buffer.from(partialResponse.slice(0, 32))

  return {
    raw_ivk,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

function processNullifierResponse(response: Buffer) {
  console.log("Processing get nullifier response")

  const partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  const raw_nf = Buffer.from(partialResponse.slice(0, 32))

  return {
    raw_nf,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}


function processOutgoingViewingKeyResponse(response: Buffer) {
  console.log("Processing get OVK response")

  const partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const raw_ovk = Buffer.from(partialResponse.slice(0, 32))

  return {
    raw_ovk,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export default class NamadaApp {
  transport

  constructor(transport: Transport) {
    this.transport = transport
    if (!transport) {
      throw new Error('Transport has not been defined')
    }
  }

  static prepareChunks(message: Buffer, serializedPathBuffer?: Buffer) {
    const chunks = []

    // First chunk (only path)
    if (serializedPathBuffer !== undefined) {
      // First chunk (only path)
      chunks.push(serializedPathBuffer!)
    }

    const messageBuffer = Buffer.from(message)

    const buffer = Buffer.concat([messageBuffer])
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE
      if (i > buffer.length) {
        end = buffer.length
      }
      chunks.push(buffer.slice(i, end))
    }

    return chunks
  }

  async signGetChunks(path: string, message: Buffer) {
    return NamadaApp.prepareChunks(message, serializePath(path))
  }

  async getVersion(): Promise<ResponseVersion> {
    return getVersion(this.transport).catch(err => processErrorResponse(err))
  }

  async getAppInfo(): Promise<ResponseAppInfo> {
    return this.transport.send(0xb0, 0x01, 0, 0).then(response => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const result: { errorMessage?: string; returnCode?: LedgerError } = {}

      let appName = 'err'
      let appVersion = 'err'
      let flagLen = 0
      let flagsValue = 0

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.errorMessage = 'response format ID not recognized'
        result.returnCode = LedgerError.DeviceIsBusy
      } else {
        const appNameLen = response[1]
        appName = response.slice(2, 2 + appNameLen).toString('ascii')
        let idx = 2 + appNameLen
        const appVersionLen = response[idx]
        idx += 1
        appVersion = response.slice(idx, idx + appVersionLen).toString('ascii')
        idx += appVersionLen
        const appFlagsLen = response[idx]
        idx += 1
        flagLen = appFlagsLen
        flagsValue = response[idx]
      }

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        flagRecovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flagSignedMcuCode: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flagOnboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flagPINValidated: (flagsValue & 128) !== 0,
      }
    }, processErrorResponse)
  }

  async getAddressAndPubKey(path: string): Promise<ResponseAddress> {
    console.log("Inside getAddressAndPubKey")

    const serializedPath = serializePath(path)
    return this.transport
        .send(CLA, INS.GET_PUBLIC_KEY, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [LedgerError.NoErrors])
        .then(processGetAddrResponse, processErrorResponse)
  }

  async showAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path)
    return this.transport
        .send(CLA, INS.GET_PUBLIC_KEY, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [LedgerError.NoErrors])
        .then(processGetAddrResponse, processErrorResponse)
  }

  async getShieldedAddressAndPubKey(path: number, div: Buffer): Promise<ResponseShieldedAddress> {
    console.log("Inside getShieldedAddressAndPubKey")
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
        .send(CLA, INS.GET_MASP_ADDRESS, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.concat([buf, div]), [LedgerError.NoErrors])
        .then(processGetShieldedAddrResponse, processErrorResponse)
  }

  async showShieldedAddressAndPubKey(path: number, div: Buffer): Promise<ResponseShieldedAddress> {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
        .send(CLA, INS.GET_MASP_ADDRESS, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, Buffer.concat([buf, div]), [LedgerError.NoErrors])
        .then(processGetShieldedAddrResponse, processErrorResponse)
  }

  async getIncomingViewingKey(path: number): Promise<ResponseIncomingViewingKey> {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
        .send(CLA, INS.GET_IVK, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [LedgerError.NoErrors])
        .then(processIncomingViewingKeyResponse, processErrorResponse)
  }

  async getOutgoingViewingKey(path: number): Promise<ResponseOutgoingViewingKey> {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
        .send(CLA, INS.GET_OVK, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [LedgerError.NoErrors])
        .then(processOutgoingViewingKeyResponse, processErrorResponse)
  }

  async getNullifier(pos: Uint8Array, cm: Buffer): Promise<ResponseNullifier> {
    return this.transport
        .send(CLA, INS.GET_NF, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.concat([pos, cm]), [LedgerError.NoErrors])
        .then(processNullifierResponse, processErrorResponse)
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: number = INS.SIGN_MSGPACK): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD
    const p2 = 0
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST
    }

    return this.transport
        .send(CLA, ins, payloadType, p2, chunk, [
          LedgerError.NoErrors,
          LedgerError.DataIsInvalid,
          LedgerError.BadKeyHandle,
          LedgerError.SignVerifyError,
        ])
        .then((response: Buffer) => {
          const errorCodeData = response.slice(-2)
          const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
          let errorMessage = errorCodeToString(returnCode)

          if (
              returnCode === LedgerError.BadKeyHandle ||
              returnCode === LedgerError.DataIsInvalid ||
              returnCode === LedgerError.SignVerifyError
          ) {
            errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
          }

          if (returnCode === LedgerError.NoErrors && response.length > 2) {
            const signature = response.slice(0, response.length - 2);
            return {
              // hash: response.slice(0, 32),
              // signature: response.slice(32, -2),
              signature,
              returnCode: returnCode,
              errorMessage: errorMessage,
            }
          }

          return {
            returnCode: returnCode,
            errorMessage: errorMessage,
          } as ResponseSign;
        }, processErrorResponse)
  }

  async sign(path: string, message: Buffer) {
    return this.signGetChunks(path, message).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_MSGPACK).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signature: null as null | Buffer,
        }
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_MSGPACK)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)
  }
}
