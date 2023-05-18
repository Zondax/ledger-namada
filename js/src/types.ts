import { LedgerError } from './common'

export interface ResponseBase {
  errorMessage: string
  returnCode: LedgerError
}

export interface ResponseAddress extends ResponseBase {
  publicKey: Buffer
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
  salt: Buffer
  hash: Buffer
  pubkey: Buffer
  signature: Buffer
}
export class Signature implements ISignature {
  salt: Buffer
  hash: Buffer
  pubkey: Buffer
  signature: Buffer

  isFilled: boolean

  constructor(signature?: ISignature) {
    if (signature == null) {
      this.isFilled = false
      this.salt = Buffer.from([])
      this.hash = Buffer.from([])
      this.pubkey = Buffer.from([])
      this.signature = Buffer.from([])
    } else {
      this.isFilled = true
      this.salt = signature.salt
      this.hash = signature.hash
      this.pubkey = signature.pubkey
      this.signature = signature.signature
    }
  }
}

export interface ResponseSign extends ResponseBase {
  headerSignature: Signature
  dataSignature: Signature
  codeSignature: Signature
}
