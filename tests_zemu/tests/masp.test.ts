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
import { NamadaApp, ResponseSignMasp, ResponseSpendSign } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions, MASP_TRANSFER_TX } from './common'

const sha256 = require('js-sha256')

jest.setTimeout(120000)

const MASP_MODELS = models.filter(m => m.name !== 'nanos')

describe('Masp', function () {

  test.concurrent.each(MASP_MODELS)('Get randomness', async function (m) {
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

  test.concurrent.each(MASP_MODELS)('Sign MASP', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // Compute randomness Not having effect on this test harcoded values inside
      const respSpend = await app.getSpendRandomness();
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')
      const respOutput = await app.getOutputRandomness();
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')
      const respOutput2 = await app.getOutputRandomness();
      expect(respOutput2.returnCode).toEqual(0x9000)
      expect(respOutput2.errorMessage).toEqual('No errors')

      const msg = Buffer.from(MASP_TRANSFER_TX, 'hex')

      //Sign and verify returned hash
      const respRequest = app.signMasp(hdpath, msg)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_masp`)

      const resp: ResponseSignMasp = await respRequest as ResponseSignMasp;
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

})
