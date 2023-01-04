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
const leb = require('leb128')

export const CHUNK_SIZE = 250;

export const PAYLOAD_TYPE = {
  INIT: 0x00,
  ADD: 0x01,
  LAST: 0x02,
};

export const P1_VALUES = {
  ONLY_RETRIEVE: 0x00,
  SHOW_ADDRESS_IN_DEVICE: 0x01,
  MSGPACK_FIRST: 0x00,
  MSGPACK_FIRST_ACCOUNT_ID: 0x01,
  MSGPACK_ADD: 0x80,
};

export const P2_VALUES = {
  DEFAULT: 0x00,
  MSGPACK_ADD: 0x80,
  MSGPACK_LAST: 0x00,
};

// noinspection JSUnusedGlobalSymbols
export const SIGN_VALUES_P2 = {
  DEFAULT: 0x00,
};

export const ERROR_CODE = {
  NoError: 0x9000,
}

export enum LedgerError {
  U2FUnknown = 1,
  U2FBadRequest = 2,
  U2FConfigurationUnsupported = 3,
  U2FDeviceIneligible = 4,
  U2FTimeout = 5,
  Timeout = 14,
  NoErrors = 0x9000,
  DeviceIsBusy = 0x9001,
  ErrorDerivingKeys = 0x6802,
  ExecutionError = 0x6400,
  WrongLength = 0x6700,
  EmptyBuffer = 0x6982,
  OutputBufferTooSmall = 0x6983,
  DataIsInvalid = 0x6984,
  ConditionsNotSatisfied = 0x6985,
  TransactionRejected = 0x6986,
  BadKeyHandle = 0x6a80,
  InvalidP1P2 = 0x6b00,
  InstructionNotSupported = 0x6d00,
  AppDoesNotSeemToBeOpen = 0x6e01,
  UnknownError = 0x6f00,
  SignVerifyError = 0x6f01,
}

export const ERROR_DESCRIPTION = {
  [LedgerError.U2FUnknown]: 'U2F: Unknown',
  [LedgerError.U2FBadRequest]: 'U2F: Bad request',
  [LedgerError.U2FConfigurationUnsupported]: 'U2F: Configuration unsupported',
  [LedgerError.U2FDeviceIneligible]: 'U2F: Device Ineligible',
  [LedgerError.U2FTimeout]: 'U2F: Timeout',
  [LedgerError.Timeout]: 'Timeout',
  [LedgerError.NoErrors]: 'No errors',
  [LedgerError.DeviceIsBusy]: 'Device is busy',
  [LedgerError.ErrorDerivingKeys]: 'Error deriving keys',
  [LedgerError.ExecutionError]: 'Execution Error',
  [LedgerError.WrongLength]: 'Wrong Length',
  [LedgerError.EmptyBuffer]: 'Empty Buffer',
  [LedgerError.OutputBufferTooSmall]: 'Output buffer too small',
  [LedgerError.DataIsInvalid]: 'Data is invalid',
  [LedgerError.ConditionsNotSatisfied]: 'Conditions not satisfied',
  [LedgerError.TransactionRejected]: 'Transaction rejected',
  [LedgerError.BadKeyHandle]: 'Bad key handle',
  [LedgerError.InvalidP1P2]: 'Invalid P1/P2',
  [LedgerError.InstructionNotSupported]: 'Instruction not supported',
  [LedgerError.AppDoesNotSeemToBeOpen]: 'App does not seem to be open',
  [LedgerError.UnknownError]: 'Unknown error',
  [LedgerError.SignVerifyError]: 'Sign/verify error',
};

export function errorCodeToString(statusCode: LedgerError) {
  if (statusCode in ERROR_DESCRIPTION) return ERROR_DESCRIPTION[statusCode];
  return `Unknown Status Code: ${statusCode}`;
}

function isDict(v: any) {
  return typeof v === 'object' && v !== null && !(v instanceof Array) && !(v instanceof Date);
}

export function processErrorResponse(response: any) {
  if (response) {
    if (isDict(response)) {
      if (Object.prototype.hasOwnProperty.call(response, 'statusCode')) {
        return {
          return_code: response.statusCode,
          error_message: errorCodeToString(response.statusCode),
        }
      }

      if (
        Object.prototype.hasOwnProperty.call(response, 'return_code') &&
        Object.prototype.hasOwnProperty.call(response, 'error_message')
      ) {
        return response
      }
    }
    return {
      return_code: 0xffff,
      error_message: response.toString(),
    }
  }

  return {
    return_code: 0xffff,
    error_message: response.toString(),
  }
}

const HARDENED = 0x80000000;
const DEFAULT_DER_PATH_LEN = 6;
const IDENTITY_DER_PATH_LEN = 4; // m/888'/0'/<account>

export function serializePath(path: string) {
  if (!path.startsWith('m')) {
    throw new Error(`Path should start with "m" (e.g "m/44'/5757'/5'/0/3")`);
  }

  const pathArray = path.split('/');

  let allocSize = 0;

  if (pathArray.length === DEFAULT_DER_PATH_LEN || pathArray.length === IDENTITY_DER_PATH_LEN  ) {
    allocSize = (pathArray.length - 1) * 4 + 1;
  } else {
    throw new Error(`Invalid path. (e.g "m/44'/134'/0/0/0"`);
  }

  const buf = Buffer.alloc(allocSize);
  buf.writeUInt8(pathArray.length - 1, 0)

  for (let i = 1; i < pathArray.length; i += 1) {
    let value = 0;
    let child = pathArray[i];
    if (child.endsWith("'")) {
      value += HARDENED;
      child = child.slice(0, -1);
    }

    const childNumber = Number(child);

    if (Number.isNaN(childNumber)) {
      throw new Error(`Invalid path : ${child} is not a number. (e.g "m/44'/461'/5'/0/3")`);
    }

    if (childNumber >= HARDENED) {
      throw new Error('Incorrect child value (bigger or equal to 0x80000000)');
    }

    value += childNumber;

    buf.writeUInt32LE(value, 4 * (i-1) + 1);
  }

  return buf;
}

export interface ProtoTimestamp {
  seconds: number;
  nanos: number;
}

export function serializeTimestamp(timestamp: ProtoTimestamp) {
  const TAG_TS =  Buffer.from([0x1A])
  const TAG_S =  Buffer.from([0x08])
  const TAG_N =  Buffer.from([0x10])

  const lebseconds = leb.signed.encode(timestamp.seconds)
  const lebnanos = leb.signed.encode(timestamp.nanos)

  let serialized = timestamp.seconds > 0 ? Buffer.concat([TAG_S, lebseconds]) : Buffer.from([])
  if (timestamp.nanos > 0) {
    serialized = Buffer.concat([serialized, TAG_N, lebnanos])
  }

  const timestampSize = leb.unsigned.encode(serialized.length)
  const buffer = Buffer.concat([TAG_TS, timestampSize, serialized])

  return buffer
}
