import { LedgerError } from './common'

export interface ResponseBase {
  errorMessage: string
  returnCode: LedgerError
}

export interface ResponseAddress extends ResponseBase {
  rawPubkey: Buffer
  pubkey: Buffer
  address: Buffer
}

export interface ResponseVersion extends ResponseBase {
  testMode: boolean
  major: number
  minor: number
  patch: number
  deviceLocked: boolean
  targetId: string
}

export interface ResponseAppInfo extends ResponseBase {
  appName: string
  appVersion: string
  flagLen: number
  flagsValue: number
  flagRecovery: boolean
  flagSignedMcuCode: boolean
  flagOnboarded: boolean
  flagPINValidated: boolean
}

export interface ResponseDeviceInfo extends ResponseBase {
  targetId: string
  seVersion: string
  flag: string
  mcuVersion: string
}

export interface ResponseShieldedAddress extends ResponseBase {
  raw_pkd: Buffer
  bech32m_len: number
  bech32m_addr: Buffer
}

export interface ResponseIncomingViewingKey extends ResponseBase {
  raw_ivk: Buffer
}

export interface ResponseOutgoingViewingKey extends ResponseBase {
  raw_ovk: Buffer
}

export interface ResponseNullifier extends ResponseBase {
  raw_nf: Buffer
}

export interface ISignature {
  rawPubkey: Buffer
  raw_salt: Buffer
  raw_signature: Buffer
  wrapper_salt: Buffer
  wrapper_signature: Buffer
  raw_indices: Buffer
  wrapper_indices: Buffer
}
export class Signature implements ISignature {
  rawPubkey: Buffer
  raw_salt: Buffer
  raw_signature: Buffer
  wrapper_salt: Buffer
  wrapper_signature: Buffer
  raw_indices: Buffer
  wrapper_indices: Buffer
  isFilled: boolean

  constructor(signature?: ISignature) {
    if (signature == null) {
      this.isFilled = false
      this.rawPubkey = Buffer.from([])
      this.raw_salt = Buffer.from([])
      this.raw_signature = Buffer.from([])
      this.wrapper_salt = Buffer.from([])
      this.wrapper_signature = Buffer.from([])
      this.raw_indices = Buffer.from([])
      this.wrapper_indices = Buffer.from([])
    } else {
      this.isFilled = true
      this.rawPubkey = signature.rawPubkey
      this.raw_salt = signature.raw_salt
      this.raw_signature = signature.raw_signature
      this.wrapper_salt = signature.wrapper_salt
      this.wrapper_signature = signature.wrapper_signature
      this.raw_indices = signature.raw_indices
      this.wrapper_indices = signature.wrapper_indices
    }
  }
}

export interface ResponseSign extends ResponseBase {
  signature?: Signature
}
