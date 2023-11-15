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
import { NamadaApp, Signature } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions } from './common'

const sha256 = require('js-sha256')
const leb = require('leb128')

// @ts-ignore
import ed25519 from 'ed25519-supercop'


function hashSignatureSec(pubkeys: Buffer[], salt: Buffer, hashes: { [index: number]: Buffer }, indices: Buffer, signature: Buffer | null, prefix: Uint8Array | null) {
  let hash = sha256.create();
  if (prefix != null) {
    hash.update(prefix);
  }

  hash.update(new Uint8Array([indices.length, 0, 0, 0]));
  for (let i = 0; i < (indices.length); i ++) {
    hash.update(Buffer.from(hashes[indices[i]]));
  }

  // Signer::PubKeys
  hash.update(new Uint8Array([0x01]));

  //Pubkeys
  hash.update(new Uint8Array([pubkeys.length, 0, 0, 0]));
  for (let i = 0; i < (pubkeys.length); i ++) {
    hash.update(Buffer.from(pubkeys[i]));
  }

  if(signature != null) {
    // u32 representing length
    hash.update(new Uint8Array([1, 0, 0, 0]));
    // u8 representing key
    hash.update(new Uint8Array([0x00]));
    // common::Signature
    hash.update(signature);
  } else {
    // u32 representing length
    hash.update(new Uint8Array([0, 0, 0, 0]));
  }

  return Buffer.from(hash.array());
}

const TEST_DATA = [
  {
    name: 'bond',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431313a35303a30392e3032323635363535302b30303a30308a0a9d27c683765cc2757ed8a697d3b193dd7353bd62e6ffd70c8dc3abf9c4b6eae7a3d67850944d0822ddab8ef169f8441b0076fe40c0c1c598ed3e68ab1b600101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171000000000000000a8610000000000000002000000028095f7d78b01000000c2e86f15843e87cf1ed58d92afd419f112284c38972052b98e18a9e04fa72eff011100000074785f72657665616c5f706b2e7761736d008095f7d78b01000021000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517', 'hex'),
    sectionHashes: {
      0: Buffer.from('5495ee5290ec771bb111b11eac340fb2ddfb09f332b13bfde7935096267c0e42', 'hex'),
      1: Buffer.from('ddc8e7f3a1463df54faae663873d8f46ca67d90a50eb6cace2cf44b707cba76a', 'hex'),
      2: Buffer.from('ddd167e7c54f7cb24c7c8231df0487b49d8fbfd5dfc51065406b50d2bbd8bf3e', 'hex'),
      0xff: Buffer.from('bfb8dee7cfb2d4887fa3ec8b5e2e928fd3b00c371c5ee0938f48557046a80613', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431313a35303a30392e3032323635363535302b30303a30308a0a9d27c683765cc2757ed8a697d3b193dd7353bd62e6ffd70c8dc3abf9c4b6eae7a3d67850944d0822ddab8ef169f8441b0076fe40c0c1c598ed3e68ab1b600101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171000000000000000a8610000000000000002000000028095f7d78b01000000c2e86f15843e87cf1ed58d92afd419f112284c38972052b98e18a9e04fa72eff011100000074785f72657665616c5f706b2e7761736d008095f7d78b01000021000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517', 'hex'),
    sectionHashes: {
      0: Buffer.from('4c33e85bb44229a5961683873e4dc8bb0dd6cad7002eee26da213218004e8a29', 'hex'),
      1: Buffer.from('649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c', 'hex'),
      2: Buffer.from('49510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e08264', 'hex'),
      3: Buffer.from('0055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70', 'hex'),
      4: Buffer.from('b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606', 'hex'),
      0xff: Buffer.from('e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_validator',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431313a35303a30392e3032323635363535302b30303a30308a0a9d27c683765cc2757ed8a697d3b193dd7353bd62e6ffd70c8dc3abf9c4b6eae7a3d67850944d0822ddab8ef169f8441b0076fe40c0c1c598ed3e68ab1b600101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171000000000000000a8610000000000000002000000028095f7d78b01000000c2e86f15843e87cf1ed58d92afd419f112284c38972052b98e18a9e04fa72eff011100000074785f72657665616c5f706b2e7761736d008095f7d78b01000021000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517', 'hex'),
    sectionHashes: {
      0: Buffer.from('0b9772159d5a6760afad9c18e1837d7bdcb33428c886739bb47f4113c9ff8808', 'hex'),
      1: Buffer.from('b94b385c5bb780bccb7ed816a59209963ba92aeb37ff17bd17bac5439aa28bdf', 'hex'),
      2: Buffer.from('d856401c57c3756bd9b7a8596b30bdbbdcd84ea1369082709085945a75593266', 'hex'),
      3: Buffer.from('bf1978c1d2c865cbd998c85270a41e91bf38370cdce5645c58b3936b29896733', 'hex'),
      0xff: Buffer.from('2635e4198dd017e15766f80a76fd701fbe22409045ee30215adc762ed19f1ab6', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431313a35303a30392e3032323635363535302b30303a30308a0a9d27c683765cc2757ed8a697d3b193dd7353bd62e6ffd70c8dc3abf9c4b6eae7a3d67850944d0822ddab8ef169f8441b0076fe40c0c1c598ed3e68ab1b600101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171000000000000000a8610000000000000002000000028095f7d78b01000000c2e86f15843e87cf1ed58d92afd419f112284c38972052b98e18a9e04fa72eff011100000074785f72657665616c5f706b2e7761736d008095f7d78b01000021000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517', 'hex'),
    sectionHashes: {
      0: Buffer.from('cc725ee2571dda7143662accd8cb6685c45ab704891f5aa1046a8ad7f4ba2f81', 'hex'),
      1: Buffer.from('e666a12812cd9f8a2bd38973db21836fa6eeab3a915223f3e3ae3441a8736923', 'hex'),
      2: Buffer.from('70b5e945f66af7c2ded580ce153616710e6e79bf7d30c69d0915e8c18d3f2bf3', 'hex'),
      3: Buffer.from('7b5e32353abaa027c09297bf112b0722bd297c75dca19ccf9e958d8372be0440', 'hex'),
      0xff: Buffer.from('8f36472221e8257cbca0093c8ffa50f5d209445b650351030f34d32c678610d4', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_pubkeys',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431313a35303a30392e3032323635363535302b30303a30308a0a9d27c683765cc2757ed8a697d3b193dd7353bd62e6ffd70c8dc3abf9c4b6eae7a3d67850944d0822ddab8ef169f8441b0076fe40c0c1c598ed3e68ab1b600101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171000000000000000a8610000000000000002000000028095f7d78b01000000c2e86f15843e87cf1ed58d92afd419f112284c38972052b98e18a9e04fa72eff011100000074785f72657665616c5f706b2e7761736d008095f7d78b01000021000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517', 'hex'),
    sectionHashes: {
      0: Buffer.from('4c33e85bb44229a5961683873e4dc8bb0dd6cad7002eee26da213218004e8a29', 'hex'),
      1: Buffer.from('649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c', 'hex'),
      2: Buffer.from('49510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e08264', 'hex'),
      3: Buffer.from('0055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70', 'hex'),
      4: Buffer.from('b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606', 'hex'),
      5: Buffer.from('d6696623fc2de31730650870dd25ba2d8ba3d161c130294b9ad3640eda9a5d0b', 'hex'),
      0xff: Buffer.from('e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_address',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431313a35303a30392e3032323635363535302b30303a30308a0a9d27c683765cc2757ed8a697d3b193dd7353bd62e6ffd70c8dc3abf9c4b6eae7a3d67850944d0822ddab8ef169f8441b0076fe40c0c1c598ed3e68ab1b600101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171000000000000000a8610000000000000002000000028095f7d78b01000000c2e86f15843e87cf1ed58d92afd419f112284c38972052b98e18a9e04fa72eff011100000074785f72657665616c5f706b2e7761736d008095f7d78b01000021000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517', 'hex'),
    sectionHashes: {
      0: Buffer.from('4c33e85bb44229a5961683873e4dc8bb0dd6cad7002eee26da213218004e8a29', 'hex'),
      1: Buffer.from('649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c', 'hex'),
      2: Buffer.from('49510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e08264', 'hex'),
      3: Buffer.from('0055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70', 'hex'),
      4: Buffer.from('b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606', 'hex'),
      5: Buffer.from('d953f2b8f418f44360b13b17e4f85710a84131180492033a0ea5b2231766d441', 'hex'),
      0xff: Buffer.from('e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970', 'hex'),
    } as { [index: number]: Buffer },
  },
]

jest.setTimeout(120000)

describe.each(models)('Transactions', function (m) {
  test.concurrent.each(TEST_DATA)('Sign transaction', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      // console.log(resp_addr)

      const respRequest = app.sign(hdpath, data.blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-${data.name}`)

      const resp = await respRequest
      // console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const signature = resp.signature ?? new Signature()
      expect(signature.pubkey).toEqual(resp_addr.publicKey);

      // Verify raw signature
      const unsignedRawSigHash = hashSignatureSec([], signature.raw_salt, data.sectionHashes, signature.raw_indices, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.pubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03]);
      const rawHash: Buffer = hashSignatureSec([signature.pubkey], signature.raw_salt, data.sectionHashes, signature.raw_indices, signature.raw_signature, prefix);
      const tmpHashes = {...data.sectionHashes};

      tmpHashes[Object.keys(tmpHashes).length - 1] = rawHash;

      const unsignedWrapperSigHash = hashSignatureSec([], signature.wrapper_salt, tmpHashes, signature.wrapper_indices, null, null);
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.publicKey.subarray(1));

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
