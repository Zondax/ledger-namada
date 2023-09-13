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


function hashSignatureSec(pubkey: Buffer, salt: Buffer, hashes: Buffer[], indices: Buffer, signature: Buffer | null, prefix: Uint8Array | null) {
  let hash = sha256.create();
  if (prefix != null) {
    hash.update(prefix);
  }
  hash.update(salt);
  hash.update(new Uint8Array([indices.length, 0, 0, 0]));
  for (let i = 0; i < (indices.length); i ++) {
    hash.update(Buffer.from(hashes[indices[i]]));
  }
  hash.update(pubkey);
  if(signature != null) {
    hash.update(new Uint8Array([0x01]));
    hash.update(signature);
  } else {
    hash.update(new Uint8Array([0x00]));
  }
  return Buffer.from(hash.array());
}

const TEST_DATA = [
  {
    name: 'bond',
    blob: Buffer.from('1e0000006532652d746573742e6265303236663035666665383631336335376464350023000000323032332d30392d31315431343a32323a31322e3630383138323331302b30303a30303a37bbaf035307da51bd4b3910618756ec224baddae09336100c31cafa38cc363a5a67c5f8ae4736c88af40f98db6d78d8b626c006e44a318ef175c790522eef010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008f70e8a40f7b1eb5e33f6da0fa6ae8cccb9037c158ffbef6e94cbeea8943139d0100000000000000204e00000000000000000200000002ab149f848a010000008d1ddbeb397209c5efa22dd57fbdb31825d67c2942441cb2612583ec2593831a00ab149f848a0100004b00000000e5c4af3b80a9d2bf260fce4b9fd21a29aaf2874500e9a4350000000000000000000000000000000000000000000000000000000001002161fa3274d9f5cc0021fdd23ad6cdc941e79f86', 'hex'),
    sectionHashes: [
      Buffer.from('4e3ddd5b4f43591469222e2205b3dc667bc44b018c5675d52d7c11521292fb7e', 'hex'),
      Buffer.from('3a37bbaf035307da51bd4b3910618756ec224baddae09336100c31cafa38cc36', 'hex'),
      Buffer.from('3a5a67c5f8ae4736c88af40f98db6d78d8b626c006e44a318ef175c790522eef', 'hex'),
    ],
    dataHash: 1,
    codeHash: 2,
  },
  {
    name: 'init_account',
    blob: Buffer.from('1e0000006532652d746573742e6265303236663035666665383631336335376464350023000000323032332d30392d31315431343a32343a30302e3430343231373831382b30303a3030e5a2c3aabcb288511bbc66d79d0b43b6178467416fff2382f1278d9f9d449b57fb290a5b3c5e6f09734775b9bc5fc2ef4f2c195b5451b8ae1b3c295d99268989010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600d2c4b3de7d146a9e967d179e8aededc63586e07c1f3e27218fbadafdff2df4e10200000000000000204e00000000000000000300000001bfb9a0848a01000000f93b90d5a0226c79159edd48f2801e7a12525751b937fda58525a8fc8b42d74502c0b9a0848a01000000d527ea17b417fca1a72d6a26abc34219630efcad4701e629a89e026e06ee06c100c0b9a0848a010000460000000100000000d2c4b3de7d146a9e967d179e8aededc63586e07c1f3e27218fbadafdff2df4e1145c0edaf591acc7472c6c5f6190a15f787e33a98cc286bb64383a210784051501', 'hex'),
    sectionHashes: [
      Buffer.from('d7bc97fd8c9d39e93966d4c5552bc835a039f76a08434f3a037ff8ca93f5b6c0', 'hex'),
      Buffer.from('145c0edaf591acc7472c6c5f6190a15f787e33a98cc286bb64383a2107840515', 'hex'),
      Buffer.from('e5a2c3aabcb288511bbc66d79d0b43b6178467416fff2382f1278d9f9d449b57', 'hex'),
      Buffer.from('fb290a5b3c5e6f09734775b9bc5fc2ef4f2c195b5451b8ae1b3c295d99268989', 'hex'),
    ],
    dataHash: 2,
    codeHash: 3,
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1e0000006532652d746573742e6265303236663035666665383631336335376464350023000000323032332d30392d31315431343a32323a32342e3739343035353433302b30303a3030ce41c9cffac02c6bf36c96c7668c6ddb276053c125bbf1ee23d00cac6876237dd6cf2a983a7df1e44ca01c80988242218957f35c07a6863ece3730d5ab378da6010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600d2c4b3de7d146a9e967d179e8aededc63586e07c1f3e27218fbadafdff2df4e10100000000000000204e0000000000000000040000000147449f848a010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e0148449f848a01000000920ecbc5cc6286a57743ed18027dd68cf0c6623b9c6c6b366df693ba93f2cda90250449f848a01000000e605bb96ff8b6ad1e10491a81590d15ed792f87b0382d1faee9966cb25a090280050449f848a010000700000000031320e785b4422f2a43f4810dad0c05355cd5c1eda4f1e15a6fbfcae448123770071006fa869bbf660768cc4962a415e19cce0a4a20001fa4b27beb1ceac9346dacba94b645cb0033490c6b4e482653ee882bdfc07ad6c0c0000000000000018000000000000001e00000000000000', 'hex'),
    sectionHashes: [
      Buffer.from('3e21c198c5b9d5cdb24a1405e91862142c6c3d5a6e9d47d538894fa6d1154906', 'hex'),
      Buffer.from('31320e785b4422f2a43f4810dad0c05355cd5c1eda4f1e15a6fbfcae44812377', 'hex'),
      Buffer.from('fa4b27beb1ceac9346dacba94b645cb0033490c6b4e482653ee882bdfc07ad6c', 'hex'),
      Buffer.from('ce41c9cffac02c6bf36c96c7668c6ddb276053c125bbf1ee23d00cac6876237d', 'hex'),
      Buffer.from('d6cf2a983a7df1e44ca01c80988242218957f35c07a6863ece3730d5ab378da6', 'hex'),
    ],
    dataHash: 3,
    codeHash: 4,
  },
  {
    name: 'init_validator',
    blob: Buffer.from('1e0000006532652d746573742e6265303236663035666665383631336335376464350023000000323032332d30392d31315431343a32333a34382e3130373737333839372b30303a30304f84926da2120d8060ad289e54782ea867db2a9c959a120edb94317bf82b8c89c1121722979a177cb24c2bfe66eb542f163661ecfb0bf01b4ff63a8c53df94ba010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600d2c4b3de7d146a9e967d179e8aededc63586e07c1f3e27218fbadafdff2df4e10100000000000000204e000000000000000003000000018b89a0848a01000000f93b90d5a0226c79159edd48f2801e7a12525751b937fda58525a8fc8b42d745028c89a0848a0100000091ce97ff0bfa49ce9baa7585ae7e2c0514e91a66c625502b4aced635da5b021a008c89a0848a0100008f0100000200000000d2c4b3de7d146a9e967d179e8aededc63586e07c1f3e27218fbadafdff2df4e1008f70e8a40f7b1eb5e33f6da0fa6ae8cccb9037c158ffbef6e94cbeea8943139d0200d978a9a06dc78c73c61ebe68187a263bd8129674ce1ec705a6b1766aa89088cc02e5ccd5eecbe2684853a7768970294c0eebc718de110846062a12fdfaae558dd8031d9eea3e319675a5871369cae8d84ad8e73785f4e7dbc556feb4e48f9ca99d9800ad34c3481e08abd82c54bcae80c3dd220dbbfe4e96ad7a5477301e58498af33160000000f54cd88a6b0e8c36535af64f070a4f70794abd6381ff90ee64cca542fa0ffbd29f433d6d1e449e6a0bbcc99414a49311673061a9e2bfa65f5dae50ff2f9f436e2a75c19341c2251a78170eedeb1074306d5aee0983c428e3d70f33ce9771940700743ba40b00000000000000000000000000000000000000000000000000000000e40b540200000000000000000000000000000000000000000000000000000064b7bc7a33a09f86181c7f08e2c0273d6acb29f3f5c1df971dd6e8644b0feaa0', 'hex'),
    sectionHashes: [
      Buffer.from('200d012080ad514e6e8ec9dcafaf1e4e083658e2fbcb8e19726c99be1b9afab4', 'hex'),
      Buffer.from('64b7bc7a33a09f86181c7f08e2c0273d6acb29f3f5c1df971dd6e8644b0feaa0', 'hex'),
      Buffer.from('4f84926da2120d8060ad289e54782ea867db2a9c959a120edb94317bf82b8c89', 'hex'),
      Buffer.from('c1121722979a177cb24c2bfe66eb542f163661ecfb0bf01b4ff63a8c53df94ba', 'hex'),
    ],
    dataHash: 2,
    codeHash: 3,
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1e0000006532652d746573742e6265303236663035666665383631336335376464350023000000323032332d30392d31315431343a32333a33352e3237353930373832312b30303a3030204148c6e7f19a7753e53d4f000730186e46d7f34acb17212c11f07ec8d74756b3e48c5dd910ffac8fa81536d0ee4694810bda006d66020c2fa348c11ae64b8a010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008f70e8a40f7b1eb5e33f6da0fa6ae8cccb9037c158ffbef6e94cbeea8943139d0100000000000000204e000000000000000003000000019757a0848a01000000f93b90d5a0226c79159edd48f2801e7a12525751b937fda58525a8fc8b42d745029857a0848a010000008f5934e4fcca4e7d3c58e1c0b8722ce0a948efa6b99e7801dd1c16f8ea22fb59009857a0848a0100007d000000002161fa3274d9f5cc0021fdd23ad6cdc941e79f8601308ff5455e678a9360e0910c6594340fe71b06f87af0a401ad0af81ccd83dfd20200000000d2c4b3de7d146a9e967d179e8aededc63586e07c1f3e27218fbadafdff2df4e1008f70e8a40f7b1eb5e33f6da0fa6ae8cccb9037c158ffbef6e94cbeea8943139d00', 'hex'),
    sectionHashes: [
      Buffer.from('3123d089ba2b44db9f7255e11c1b3015da77d2aacc3c63addb058aacd06c6b97', 'hex'),
      Buffer.from('308ff5455e678a9360e0910c6594340fe71b06f87af0a401ad0af81ccd83dfd2', 'hex'),
      Buffer.from('204148c6e7f19a7753e53d4f000730186e46d7f34acb17212c11f07ec8d74756', 'hex'),
      Buffer.from('b3e48c5dd910ffac8fa81536d0ee4694810bda006d66020c2fa348c11ae64b8a', 'hex'),
    ],
    dataHash: 2,
    codeHash: 3,
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
      console.log(resp_addr)

      const respRequest = app.sign(hdpath, data.blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-${data.name}`)

      const resp = await respRequest
      console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const signature = resp.signature ?? new Signature()
      expect(signature.pubkey).toEqual(resp_addr.publicKey);

      // Verify raw signature
      const unsignedRawSigHash = hashSignatureSec(signature.pubkey, signature.raw_salt, data.sectionHashes, signature.raw_indices, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.pubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03]);
      const rawHash: Buffer = hashSignatureSec(signature.pubkey, signature.raw_salt, data.sectionHashes, signature.raw_indices, signature.raw_signature, prefix);
      const tmpHashes: Buffer[] = data.sectionHashes.concat([rawHash]);
      const unsignedWrapperSigHash = hashSignatureSec(signature.pubkey, signature.wrapper_salt, tmpHashes, signature.wrapper_indices, null, null);
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.publicKey.subarray(1));

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
