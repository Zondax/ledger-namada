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
import Transport from '@ledgerhq/hw-transport'
import {
  KeyResponse,
  NamadaKeys,
  ResponseAddress,
  ResponseAppInfo,
  ResponseBase,
  ResponseGetConvertRandomness,
  ResponseGetOutputRandomness,
  ResponseGetSpendRandomness,
  ResponseSign,
  ResponseSignMasp,
  ResponseVersion,
} from './types'

import { CHUNK_SIZE, errorCodeToString, LedgerError, P1_VALUES, PAYLOAD_TYPE, processErrorResponse, serializePath } from './common'

import { CLA, INS } from './config'
import {
  getSignatureResponse,
  processConvertRandomnessResponse,
  processGetAddrResponse,
  processGetKeysResponse,
  processMaspSign,
  processOutputRandomnessResponse,
  processSpendRandomnessResponse,
  processSpendSignResponse,
} from './processResponses'

export { LedgerError }
export * from './types'

export class NamadaApp {
  transport: Transport

  constructor(transport: Transport) {
    if (!transport) {
      throw new Error('Transport has not been defined')
    }

    this.transport = transport
  }

  async prepareChunks(serializedPath: Buffer, message: Buffer) {
    const chunks = []

    chunks.push(serializedPath)
    for (let i = 0; i < message.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE
      if (i > message.length) {
        end = message.length
      }
      chunks.push(message.subarray(i, end))
    }

    return chunks
  }

  async getVersion(): Promise<ResponseVersion> {
    return this.transport.send(CLA, INS.GET_VERSION, 0, 0).then((response: any) => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      let targetId = 0
      if (response.length >= 9) {
        /* eslint-disable no-bitwise */
        targetId = (response[5] << 24) + (response[6] << 16) + (response[7] << 8) + (response[8] << 0)
        /* eslint-enable no-bitwise */
      }

      return {
        returnCode: returnCode,
        errorMessage: errorCodeToString(returnCode),
        // ///
        testMode: response[0] !== 0,
        major: response[1],
        minor: response[2],
        patch: response[3],
        deviceLocked: response[4] === 1,
        targetId: targetId.toString(16),
      }
    }, processErrorResponse)
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
    const serializedPath = serializePath(path)
    return this.transport
      .send(CLA, INS.GET_TRANSPARENT_ADDRESS, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse)
  }

  async showAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path)
    return this.transport
      .send(CLA, INS.GET_TRANSPARENT_ADDRESS, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse)
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: number): Promise<ResponseBase> {
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
        const errorCodeData = response.subarray(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.subarray(0, response.length - 2).toString('ascii')}`
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          return {
            signature: getSignatureResponse(response),
            returnCode,
            errorMessage,
          }
        }

        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        } as ResponseSign
      }, processErrorResponse)
  }

  async signSendMaspChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: number): Promise<ResponseBase> {
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
        const errorCodeData = response.subarray(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.subarray(0, response.length - 2).toString('ascii')}`
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          return processMaspSign(response);
        }

        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        } as ResponseSignMasp
      }, processErrorResponse)
  }

  async sign(path: string, message: Buffer): Promise<ResponseSign> {
    const serializedPath = serializePath(path)

    return this.prepareChunks(serializedPath, message).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN).then(async response => {
        let result: ResponseSign = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
        }

        for (let i = 1; i < chunks.length; i++) {
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)
  }

  async retrieveKeys(path: string, keyType: NamadaKeys, showInDevice: boolean): Promise<KeyResponse> {
    const serializedPath = serializePath(path)
    const p1 = showInDevice ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE
    return this.transport
      .send(CLA, INS.GET_KEYS, p1, keyType, serializedPath, [LedgerError.NoErrors])
      .then(result => processGetKeysResponse(result, keyType) as KeyResponse, processErrorResponse)
  }

  async signMaspSpends(path: string, masp: Buffer): Promise<ResponseSignMasp> {
    const serializedPath = serializePath(path)
    return this.prepareChunks(serializedPath, masp).then(chunks => {
      return this.signSendMaspChunk(1, chunks.length, chunks[0], INS.SIGN_MASP_SPENDS).then(async response => {
        let result: ResponseSign = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
        }

        for (let i = 1; i < chunks.length; i++) {
          result = await this.signSendMaspChunk(1 + i, chunks.length, chunks[i], INS.SIGN_MASP_SPENDS)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)
  }

  async getSpendRandomness(): Promise<ResponseGetSpendRandomness> {
    return this.transport
      .send(CLA, INS.GET_SPEND_RAND, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processSpendRandomnessResponse, processErrorResponse);
  }

  async getOutputRandomness(): Promise<ResponseGetOutputRandomness> {
    return this.transport
      .send(CLA, INS.GET_OUTPUT_RAND, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processOutputRandomnessResponse, processErrorResponse);
  }

  async getConvertRandomness(): Promise<ResponseGetConvertRandomness> {
    return this.transport
      .send(CLA, INS.GET_CONVERT_RAND, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processConvertRandomnessResponse, processErrorResponse);
  }

  async getSpendSignature() {
    return this.transport
      .send(CLA, INS.EXTRACT_SPEND_SIGN, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processSpendSignResponse, processErrorResponse);
  }
}
