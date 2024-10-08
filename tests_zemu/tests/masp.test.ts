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
import Zemu from '@zondax/zemu'
import { NamadaApp, ResponseSignMasp, ResponseSpendSign, Signature } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions, MASP_TRANSFER_SIGNING_TX, MASP_TRANSFER_TX } from './common'
import { hashSignatureSec } from './utils'

// @ts-ignore
import ed25519 from 'ed25519-supercop'

jest.setTimeout(120000)

const MASP_MODELS = models.filter(m => m.name !== 'nanos')

const TEST_SIGN_DATA = {
  name: 'transfer',
  blob: Buffer.from(MASP_TRANSFER_SIGNING_TX, 'hex'),
  sectionHashes: {
    0: Buffer.from('af859437564c2c660a42903d9dca0686f1229cf4039894cf2b4cc4529decde6f', 'hex'),
    1: Buffer.from('1f07d555db2430f5dbf51e1f70ce0852affeb8d5791a6957a9895b40ce79e726', 'hex'),
    2: Buffer.from('20b9054f4e22fdaeda9d89999fee8c91493873ccaa268df016e0fe86e55de363', 'hex'),
    3: Buffer.from('a4fa85bd4b2205d4fd51e438bf65c95edf3503236ec0ffbe3a471524af2efa24', 'hex'),
    4: Buffer.from('0cadb91730d8d5904469534807019c50300e492afd8aa118d91482c5c8f7d657', 'hex'),
    5: Buffer.from('229f900de2dd6d43affc2822cceac915bdfba7e9b001f435f42a677c69708aaa', 'hex'),
    6: Buffer.from('21085924ad08eb3b0934a9f558c9a34d89180defbb4bb583747e519073f2399e', 'hex'),
    0xff: Buffer.from('95d70ed16980f4cab39179b420fe39b5d0209eae016778307bf3bc43d4b9999a', 'hex'),
  } as { [index: number]: Buffer },
}

describe('Masp', function () {
  test.concurrent.each(MASP_MODELS)('Get randomness', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respSpend = await app.getSpendRandomness()
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respSpend1 = await app.getSpendRandomness()
      console.log(respSpend1)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness()
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness()
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Sign MASP Spends', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // Compute randomness Not having effect on this test harcoded values inside
      const respSpend = await app.getSpendRandomness()
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')
      const respConvert = await app.getConvertRandomness()
      expect(respConvert.errorMessage).toEqual('No errors')
      const respOutput = await app.getOutputRandomness()
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const msg = Buffer.from(MASP_TRANSFER_TX, 'hex')

      //Sign and verify returned hash
      const respRequest = app.signMaspSpends(hdpath, msg)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_masp_spends`)

      const resp: ResponseSignMasp = (await respRequest) as ResponseSignMasp
      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      //Extract Signture for the spend
      const respSpendSign = app.getSpendSignature()
      const resp2: ResponseSpendSign = (await respSpendSign) as ResponseSpendSign
      console.log(resp2)
      expect(resp2.returnCode).toEqual(0x9000)
      expect(resp2.errorMessage).toEqual('No errors')

      // Try to get next non existant signature
      const respSpendSign2 = app.getSpendSignature()
      const resp3: ResponseSpendSign = (await respSpendSign2) as ResponseSpendSign
      console.log(resp3)
      expect(resp3.returnCode).toEqual(0x6984)
      expect(resp3.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Sign MASP', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      // console.log(resp_addr)

      const respRequest = app.sign(hdpath, TEST_SIGN_DATA.blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-masp-${TEST_SIGN_DATA.name}`)

      const resp = await respRequest
      // console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const signature = resp.signature ?? new Signature()
      expect(signature.rawPubkey).toEqual(resp_addr.rawPubkey)
      console.log(signature)
      // Verify raw signature
      const unsignedRawSigHash = hashSignatureSec([], signature.raw_salt, TEST_SIGN_DATA.sectionHashes, signature.raw_indices, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.rawPubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03])
      const rawHash: Buffer = hashSignatureSec(
        [signature.rawPubkey],
        signature.raw_salt,
        TEST_SIGN_DATA.sectionHashes,
        signature.raw_indices,
        signature.raw_signature,
        prefix,
      )
      const tmpHashes = { ...TEST_SIGN_DATA.sectionHashes }

      tmpHashes[Object.keys(tmpHashes).length - 1] = rawHash

      const unsignedWrapperSigHash = hashSignatureSec([], signature.wrapper_salt, tmpHashes, signature.wrapper_indices, null, null)
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.rawPubkey.subarray(1))

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Clean randomness Buffers', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respSpend = await app.getSpendRandomness()
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness()
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness()
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')

      const respClean = await app.cleanRandomnessBuffers()
      console.log(respClean)
      expect(respClean.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Wrong MASP starting instruction', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respClean = await app.cleanRandomnessBuffers()
      console.log(respClean)
      expect(respClean.returnCode).toEqual(0x9000)

      // Wrong MASP starting INS no randomness was computed or spends signed
      const resp = await app.getSpendSignature()

      // Expect the specific return code and error message
      expect(resp.returnCode).toEqual(27012)
      expect(resp.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Wrong MASP sequence', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // First step: compute randomness
      const respSpend = await app.getSpendRandomness()
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness()
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness()
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')

      // Missing spend signature and trying to extract the signatures
      const resp = await app.getSpendSignature()
      console.log(resp)

      // Expect the specific return code and error message
      expect(resp.returnCode).toEqual(27012)
      expect(resp.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })
})
