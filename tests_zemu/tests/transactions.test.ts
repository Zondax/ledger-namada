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

const TEST_DATA = [
  {
    name: 'transfer',
    blob: Buffer.from('23000000323032332d30342d31395431343a31393a33382e3131343438313335312b30303a303001000000000000000000280000003442383846423931334130373636453330413030423246423841413239343941373130453234453600c84e80132c95e91fabaaf941484cda0bedf2c26c99a7f9a89a84c9f08146b6ca05000000000000000000000000000000b91572f3df344a146b2cb57071d0250b826365b60bcfdb89673e7eb296ec1363453cb84daea043f101504b77129197d6c80e62d66e8eb1c8e4cb1da20fa219fd000500000000029de299870100009200000000280000003546304432464344343431313437414345323633354539353345453744373833363937333632363600280000004144323044314346464434454645334633434634353241464243434439414443314236413733333100280000003344323334443145333945313831443532443031383036354531343243413931433035324245334500c0f35e0100000000000002029de2998701000000c63868b8102713771bf4db94514b892308bda0744c691f55d6cbfda5f5698c09030a9de29987010000b91572f3df344a146b2cb57071d0250b826365b60bcfdb89673e7eb296ec136300ada3372e8c6011c6132981a5422d23b7dd7c1da745be6de451ce275820a88617daa79a99bb4bea314f2a0964f39a0c8396b891cc5e8f7585758ab6a3db74e20d00c84e80132c95e91fabaaf941484cda0bedf2c26c99a7f9a89a84c9f08146b6ca030b9de29987010000453cb84daea043f101504b77129197d6c80e62d66e8eb1c8e4cb1da20fa219fd00ec32dfb11ab1d2f149ef419c3ccff56ef7d9a0206bb6e011a7c8ae09c0faa442780e6920c35ea4f0a470f83b2bfd9c568c2eaa170eba48f9be397a9982dede0e00c84e80132c95e91fabaaf941484cda0bedf2c26c99a7f9a89a84c9f08146b6ca030b9de299870100006c8a8d627197015b83bf628b51f955f1f56e88ff62f8ce1315871c6dbfeefaaf000a47ecf1880234a6a008f88bb874a31740c22a0c7ee8709c73ec6018488718a4642ae978ab54d277b8eef0cf429c3ae3e012dac48c1451c8b93586c29ed22d0f00c84e80132c95e91fabaaf941484cda0bedf2c26c99a7f9a89a84c9f08146b6ca', 'hex'),
  },
]

jest.setTimeout(60000)

describe.each(models)('Transactions', function (m) {
  test.concurrent.each(TEST_DATA)('Sign transaction', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      console.log(resp_addr)

      const respRequest = app.sign(hdpath, data.blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-${data.name}`)

      const resp = await respRequest
      console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      // let signatureOK = ed25519.verify(resp.signature, bytes_to_sign, resp_addr.publicKey)
      // expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
