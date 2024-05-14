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
import { NamadaApp, NamadaKeys, ResponseAddress, ResponseProofGenKey, ResponseSignMasp, ResponseViewKey } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions, expectedKeys, MASP_TRANSFER_TX } from './common'

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

      const resp = await app.getMASPRandomness(hdpath,1,2,1);
      console.log(resp.spend_randomness)

      // log the first 32 bytes of the spend randomness = value commitment randomness
      console.log(resp.spend_randomness.subarray(0, 32).toString('hex'))

      // log the last 32 bytes of the spend randomness = spend auth 
      console.log(resp.spend_randomness.subarray(32, 64).toString('hex'))

      expect(resp.spend_randomness.length).toEqual(64)
      expect(resp.output_randomness.length).toEqual(128)
      expect(resp.convert_randomness.length).toEqual(32)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models.slice(1))('Sign MASP', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp1 = await app.getMASPRandomness(hdpath,1,1,0);
      console.log(resp1)

      const msg = Buffer.from(MASP_TRANSFER_TX, 'hex')

      const respRequest = app.signMasp(hdpath, msg)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_masp`)

      const resp: ResponseSignMasp = await respRequest as ResponseSignMasp;
      console.log(resp)
      console.log(resp.signatures.subarray(0, 32).toString('hex'));
      console.log(resp.signatures.subarray(32, 64).toString('hex'));

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

})
