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
  ResponseAddress,
  ResponseAppInfo,
  ResponseSign,
  ResponseVersion
} from './types'

import {
  CHUNK_SIZE,
  errorCodeToString,
  LedgerError,
  P1_VALUES,
  PAYLOAD_TYPE,
  processErrorResponse,
  ProtoTimestamp,
  serializePath,
  serializeTimestamp,
} from './common'

import {CLA, INS} from "./config";
import { processGetAddrResponse } from './processResponses';

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

  async prepareChunks(serializedPath: Buffer, code: Buffer, data: Buffer, timestamp: Buffer) {
    const chunks = []
    const buffCodeSize = Buffer.alloc(4)
    const buffDataSize = Buffer.alloc(4)
    buffCodeSize.writeUInt32LE(code.length, 0)
    buffDataSize.writeUInt32LE(data.length, 0)

    chunks.push(serializedPath)
    const message = Buffer.concat([buffCodeSize, buffDataSize, code, data, timestamp])

    for (let i = 0; i < message.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE
      if (i > message.length) {
        end = message.length
      }
      chunks.push(message.slice(i, end))
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
        device_locked: response[4] === 1,
        target_id: targetId.toString(16),
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
        .send(CLA, INS.GET_PUBLIC_KEY, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [LedgerError.NoErrors])
        .then(processGetAddrResponse, processErrorResponse)
  }

  async showAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path)
    return this.transport
        .send(CLA, INS.GET_PUBLIC_KEY, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [LedgerError.NoErrors])
        .then(processGetAddrResponse, processErrorResponse)
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: number): Promise<ResponseSign> {
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

  async signWrapper(path: string, code: Buffer, data: Buffer, timestamp: ProtoTimestamp) {
    // Serialize code, data and timestamp [seconds_LE | nanos_LE]
    const serializedTimestamp = Buffer.alloc(12)
    serializedTimestamp.writeBigUint64LE(BigInt(timestamp.seconds), 0)
    serializedTimestamp.writeUInt32LE(timestamp.nanos, 8)

    const serializedPath = serializePath(path)

    return this.prepareChunks(serializedPath, code, data, serializedTimestamp).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_WRAPPER).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signature: null as null | Buffer,
        }

        for(let i = 1; i < chunks.length; i++) {
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_WRAPPER)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)
  }


  /* Not implemented yet
  async getShieldedAddressAndPubKey(path: number, div: Buffer): Promise<ResponseShieldedAddress> {
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
  */
}
