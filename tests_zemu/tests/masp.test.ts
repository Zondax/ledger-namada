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

import Zemu, { ButtonKind, zondaxMainmenuNavigation } from '@zondax/zemu'
import { NamadaApp, NamadaKeys, ResponseAddress, ResponseProofGenKey, ResponseSignMasp, ResponseSpendSign, ResponseViewKey } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions, expectedKeys, MASP_TRANSFER_TX, MASP_TRANSFER_TX_2_SPENDS } from './common'

const sha256 = require('js-sha256')

jest.setTimeout(120000)

describe('Standard', function () {
  test.concurrent.each(models.slice(1))('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('get shielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp: ResponseAddress = await app.retrieveKeys(hdpath, NamadaKeys.PublicAddress, false) as ResponseAddress;
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('publicAddress')

      expect(resp.publicAddress?.toString('hex')).toEqual(expectedKeys.publicAddress)

    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({...defaultOptions, model: m.name,
                       approveKeyword: m.name === 'stax' ? 'Path' : '',
                       approveAction: ButtonKind.ApproveTapButton,})
      const app = new NamadaApp(sim.getTransport())

      const respRequest = app.retrieveKeys(hdpath, NamadaKeys.PublicAddress, true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_shielded`)

      const resp: ResponseAddress = await respRequest as ResponseAddress;
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('show address - reject', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({...defaultOptions, model: m.name,
                       rejectKeyword: m.name === 'stax' ? 'QR' : ''})
      const app = new NamadaApp(sim.getTransport())

      const respRequest = app.retrieveKeys(hdpath, NamadaKeys.PublicAddress, true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-show_address_shielded_reject`)

      const resp: ResponseAddress = await respRequest as ResponseAddress;
      console.log(resp)

      expect(resp.returnCode).toEqual(0x6986)
      expect(resp.errorMessage).toEqual('Transaction rejected')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('show view key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respRequest = app.retrieveKeys(hdpath, NamadaKeys.ViewKey, true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_viewkey`)

      const resp: ResponseViewKey = await respRequest as ResponseViewKey;
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp.viewKey?.toString('hex')).toEqual(expectedKeys.viewKey)
      expect(resp.ivk?.toString('hex')).toEqual(expectedKeys.ivk)
      expect(resp.ovk?.toString('hex')).toEqual(expectedKeys.ovk)

    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('get proof generation key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp: ResponseProofGenKey = await app.retrieveKeys(hdpath, NamadaKeys.ProofGenerationKey, false) as ResponseProofGenKey;
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp.ak?.toString('hex')).toEqual(expectedKeys.ak)
      expect(resp.nsk?.toString('hex')).toEqual(expectedKeys.nsk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('Get randomness', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respSpend = await app.getSpendRandomness();
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respSpend1 = await app.getSpendRandomness();
      console.log(respSpend1)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness();
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness();
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('Sign MASP', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // Compute randomness
      const respSpend = await app.getSpendRandomness();
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')
      const respOutput = await app.getOutputRandomness();
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const msg = Buffer.from(MASP_TRANSFER_TX, 'hex')

      //Sign and verify returned hash
      const respRequest = app.signMasp(hdpath, msg)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_masp`)

      const resp: ResponseSignMasp = await respRequest as ResponseSignMasp;
      console.log(resp)
      let hash = sha256.create()
      hash.update(msg)
      let h = hash.digest('hex')
      expect(resp.hash.toString).toEqual(Buffer.from(h, 'hex').toString)
      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      //Extract Signture for the spend
      const respSpendSign = app.getSpendSignature();
      const resp2: ResponseSpendSign = await respSpendSign as ResponseSpendSign;
      console.log(resp2)
      expect(resp2.returnCode).toEqual(0x9000)
      expect(resp2.errorMessage).toEqual('No errors')

      // Try to get next non existant signature
      const respSpendSign2 = app.getSpendSignature();
      const resp3: ResponseSpendSign = await respSpendSign2 as ResponseSpendSign;
      console.log(resp3)
      expect(resp3.returnCode).toEqual(0x6984)
      expect(resp3.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })

    test.concurrent.each(models.slice(1))('Sign MASP 2 spends', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // Compute randomness
      const respSpend = await app.getSpendRandomness();
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')
      const respSpend2 = await app.getSpendRandomness();
      expect(respSpend2.returnCode).toEqual(0x9000)
      expect(respSpend2.errorMessage).toEqual('No errors')

      const msg = Buffer.from(MASP_TRANSFER_TX_2_SPENDS, 'hex')

      //Sign and verify returned hash
      const respRequest = app.signMasp(hdpath, msg)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_masp_2`)

      const resp: ResponseSignMasp = await respRequest as ResponseSignMasp;
      console.log(resp)
      let hash = sha256.create()
      hash.update(msg)
      let h = hash.digest('hex')
      expect(resp.hash.toString).toEqual(Buffer.from(h, 'hex').toString)
      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      //Extract Signture for the spend 1
      const respSpendSign = app.getSpendSignature();
      const resp2: ResponseSpendSign = await respSpendSign as ResponseSpendSign;
      console.log(resp2)
      expect(resp2.returnCode).toEqual(0x9000)
      expect(resp2.errorMessage).toEqual('No errors')

      //Extract Signture for the spend 2
      const respSpendSign2 = app.getSpendSignature();
      const resp3: ResponseSpendSign = await respSpendSign2 as ResponseSpendSign;
      console.log(resp3)
      expect(resp3.returnCode).toEqual(0x9000)
      expect(resp3.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

})
