/** ******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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

const TEST_DATA = [
  {
    name: 'transfer',
    blob: Buffer.from('1e0000006532652d746573742e6437323136343362616635323461356230613435350023000000323032332d30362d31395431323a35353a33382e3332323733363137372b30303a30303be971a951917f108de9490abf6523d3df8c41cc07233f2cef081abd40c6e95974e41647ae2e845ddc33ea6c16c06d6cee9a8a44bc1de6c2df9fe0e03f3312c90100e1f5050000000000280000003442383846423931334130373636453330413030423246423841413239343941373130453234453600ef8ffbbcf933342a6ba57bc159e222c7d127df1fe1ce8fa0a8dbf1f062ee6ed10100000000000000000000000000000000050000000052a2b9d3880100009200000000280000003432353745434543433933343733323342423333353238383742324338394630443341383844324100280000004236413337324337314633433833363630323541334431333732423945393644413530373932324600280000003344323334443145333945313831443532443031383036354531343243413931433035324245334500c0f35e010000000000000252a2b9d38801000000225991ddf88d81b7a587e98fc45d4efe6df3b3bc62d9ba946a829b7a2d0025ed0353a2b9d38801000074e41647ae2e845ddc33ea6c16c06d6cee9a8a44bc1de6c2df9fe0e03f3312c9006cbb07533c0134fca3ad064acee60584e58498de883ecba8d9e18bc810b7f965a1aae30815d4fc60dd0dd369351006366f7e29e807f6c39e4ba7c6a5dfe7130300ef8ffbbcf933342a6ba57bc159e222c7d127df1fe1ce8fa0a8dbf1f062ee6ed10353a2b9d3880100003be971a951917f108de9490abf6523d3df8c41cc07233f2cef081abd40c6e959006e267f5e75b3fc8f569643c2238c9f4f4e83cd557038c19b33777ed357af351241ec907f62c6a09a6dce5ea31f7a704e5ff0d1177b01132dc505825806728e0000ef8ffbbcf933342a6ba57bc159e222c7d127df1fe1ce8fa0a8dbf1f062ee6ed103daa2b9d38801000051088ae4706fd0fd1b94daad548d20c34c5a3c1737ec718cee7e4c339e86eb87008cb461064f7c61ea5592aafcd4a48a084d67fbc0e2a8a90c9387ff1a2e70a6970c70a775e2bc777b48c0828bb297376e65275b12df3832fb8dc166af1fc6fb0a00ef8ffbbcf933342a6ba57bc159e222c7d127df1fe1ce8fa0a8dbf1f062ee6ed1', 'hex'),
    headerHash: Buffer.from('8af7112e4d62d9216fabd2b5da65f692ef5f7a22fb671a543a5fa31edae4011e', 'hex'),
    dataHash: Buffer.from('74e41647ae2e845ddc33ea6c16c06d6cee9a8a44bc1de6c2df9fe0e03f3312c9', 'hex'),
    codeHash: Buffer.from('3be971a951917f108de9490abf6523d3df8c41cc07233f2cef081abd40c6e959', 'hex'),
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
      expect(resp).toHaveProperty('headerSignature')
      expect(resp).toHaveProperty('dataSignature')
      expect(resp).toHaveProperty('codeSignature')

      // Verify that hashes and pubkeys match
      expect(resp.headerSignature.hash).toEqual(data.headerHash);
      expect(resp.dataSignature.hash).toEqual(data.dataHash);
      expect(resp.codeSignature.hash).toEqual(data.codeHash);
      expect(resp.headerSignature.pubkey).toEqual(resp_addr.publicKey);

      // Verify signatures
      const headerSig = ed25519.verify( resp.headerSignature.signature,  data.headerHash,  resp_addr.publicKey);
      const dataSig = ed25519.verify(   resp.dataSignature.signature,    data.dataHash,    resp_addr.publicKey);
      const codeSig = ed25519.verify(   resp.codeSignature.signature,    data.codeHash,    resp_addr.publicKey);
      expect(headerSig && dataSig && codeSig).toEqual(true)

    } finally {
      await sim.close()
    }
  })
})
