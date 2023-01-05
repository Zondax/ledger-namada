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
import { NamadaApp } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions } from './common'

const sha256 = require('js-sha256')
const leb = require('leb128')

// @ts-ignore
import ed25519 from 'ed25519-supercop'
import { serializeTimestamp } from '@zondax/ledger-namada/dist/common'

const SIGN_WRAPPER_TEST_DATA = [
  {
    name: 'wrapper',
    code: Buffer.from('WrapperCode'),
    data: Buffer.from('WrapperData'),
    timestamp: {seconds: 1672923381, nanos: 536609000},
  },
]

jest.setTimeout(60000)

describe.each(models)('Transactions', function (m) {
  test.skip('can start and stop container', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.each(SIGN_WRAPPER_TEST_DATA)('Sign wrapper transaction', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      console.log(resp_addr)

      const respRequest = app.signWrapper(hdpath, data.code, data.data, data.timestamp)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-${data.name}`)

      const resp = await respRequest
      console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const code_hash = Buffer.from(sha256.hex(data.code), 'hex')
      const codeHashLength = leb.signed.encode(code_hash.length)
      const serializedCode = Buffer.concat([Buffer.from([0x0A]), codeHashLength , code_hash])
      const dataLength = leb.signed.encode(data.data.length)
      const serializedData = Buffer.concat([Buffer.from([0x12]), dataLength, data.data])
      const serializedTimestamp = serializeTimestamp(data.timestamp)

      const serializedOuterTxn = Buffer.concat([serializedCode, serializedData, serializedTimestamp])
      const bytes_to_sign = Buffer.from(sha256.hex(serializedOuterTxn), 'hex')

      let signatureOK = ed25519.verify(resp.signature, bytes_to_sign, resp_addr.publicKey)
      expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
