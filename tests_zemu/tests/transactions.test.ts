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
    blob: Buffer.from('1e0000006532652d746573742e6563353631326230393430336233333238396463380023000000323032332d30362d31335431383a30343a32392e3034353635373838352b30303a3030b35e401c64e395bf63d729dcfb2b6c6f180e0fd7959f232d3c7a9b6ee19ffaf43a3cde6c93bbe91ba1cbf4c48583a7d0b6bcbd4edf665491079bf8e1a6bb3de60100e1f5050000000000280000003442383846423931334130373636453330413030423246423841413239343941373130453234453600d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a01000000000000000000000000000000000500000000f53beeb5880100009200000000280000004345463235443836434144434442393646313238454431364444464142353331443334373145324500280000003032413641313942313533413738303631463237373539393032383046354337353241464633354300280000003344323334443145333945313831443532443031383036354531343243413931433035324245334500c0f35e0100000000000002f53beeb58801000000eb0ade49c13ca12b3b824c67c481f86a36536f56884bef664f2b065ceca9e1c603f63beeb5880100003a3cde6c93bbe91ba1cbf4c48583a7d0b6bcbd4edf665491079bf8e1a6bb3de60037743f9803487346da353af25536ef143c74365c797d8dc5373392e4e275706410a64b0ea0c62f3e3a77653bb90e4f3c25fdacf564c14a52407470efe3929e0000d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a03f73beeb588010000b35e401c64e395bf63d729dcfb2b6c6f180e0fd7959f232d3c7a9b6ee19ffaf4009d916591238563bceed4014ee0a20b7ea0d16e4ea3da97768e44748f0dd7e10a47e741b0fcea1f414970437848d532914a7ffb72982382c158d9f9eaa38af50300d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a038c3ceeb58801000042017852d71ee84ec043d5f1d8e83ccf2b348ba011e75d9c0b41db560748cc6f00aaf51f89bed31127e836a6e9a5f0472fb0439d670d3ed49f9c79021d769ff06fe2820c26a0b452505a3cff3615995c69d72bfa9181ecb5ec50bb942c625c1a0500d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a', 'hex'),
    headerHash: Buffer.from('8e4dd77127cc886afaf406608557297b79fc3723787321e599def50921a369a6', 'hex'),
    dataHash: Buffer.from('3a3cde6c93bbe91ba1cbf4c48583a7d0b6bcbd4edf665491079bf8e1a6bb3de6', 'hex'),
    codeHash: Buffer.from('b35e401c64e395bf63d729dcfb2b6c6f180e0fd7959f232d3c7a9b6ee19ffaf4', 'hex'),
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
