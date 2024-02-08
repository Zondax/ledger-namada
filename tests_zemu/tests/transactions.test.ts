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
    blob: Buffer.from('1c000000487a6f3561336132425f7157536e38355f5633535f523344525a615201260000002d3139383037392d30352d30355430343a30383a33352e3534343439313338372b30303a3030260000002d3233303230372d30372d33305430393a34363a30322e3239353031313835372b30303a3030b07a2c8b9950891d8d111f996d967d197b0fcaffe7b98f575e376194db3decebbe8094a1bf7bc67990ded99bf393e16e32d9da1ed390a21fcaaaaaa12012ec4ecf355f31cdb67a1cb422fe1bc207fc6a115aa1cb1ea5d9b63965d00e4050bd05017765a698290335060000000000000000000000000000000000000000000000005e00b20a1d252c58940835ba2ff13b3b0c491ae1c54900b31b654514b84e5b848df597e22abf59e3af4486cc44a878f4077270ef5ec1bebb5e7438d64ab4b9313945816213757201191ff6ae3302feda897597e4191ed63ce80aa62a544c27166cea37c5a0f96d040300000000999076898d0100003600000000e36306bc9ac083113ec3243c0de592a1b2820da312fe7e79580269820000000000000000000000000000000000000000000000000002999076898d01000000d4cbc63df8aeba10f111a5032f9312b8ad135b6ed8253bfbc57fce1a7100ccd3010c00000074785f626f6e642e7761736d0155d119d551037ef800dd6b82ec19979eddd4549371af61bdf20442c455c04da2b5a76c1105fc898ea600', 'hex'),
    sectionHashes: {
      0: Buffer.from('621b3c8c695f7b3f90548cba054086fd906b694d2e8375b5d7a2c3214308eff4', 'hex'),
      1: Buffer.from('be8094a1bf7bc67990ded99bf393e16e32d9da1ed390a21fcaaaaaa12012ec4e', 'hex'),
      2: Buffer.from('b07a2c8b9950891d8d111f996d967d197b0fcaffe7b98f575e376194db3deceb', 'hex'),
      3: Buffer.from('cf355f31cdb67a1cb422fe1bc207fc6a115aa1cb1ea5d9b63965d00e4050bd05', 'hex'),
      0xff: Buffer.from('76bebc01dd282b92e80bfac6b11e44f00d9f4dfd03127b7c88d666b0a502bceb', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1500000046315a37354e61575f746d544c7162736c5f71313500250000002b36323134362d30382d32345431393a33333a35362e3633393936323233352b30303a30301b4a30e7603606f68aa56abf4bfa2e2895c19027e1f81ed6f8c5ad1255a2302ba9b2900ad8b2bff46678176d5579cfe068f6b9575ca6a877da4385220e54856057c6004e1684170da337d4209e7b3eab69ff44bbe92c7286b6a9ec263add247d019d751f95424ee5a80000000000000000000000000000000000000000000000002500ddfd09c3c89d51db3df5a4ae5ff40747c8d0b0270102a025661d344496ccbaaf76c3909433cbb408bedca77c1dc3720313bf6ea5e0c65c38d4433997add5720f605684b0a0bb0004000000012e1a48babcfceaec00183178a2699d4025dfc4363a8ac11c7561b9bd2145a0081eadb6d83e1b420f28011e0000005f74345f5f6c5a4d6b385f6c415f695f443943735f505f5f6739305f5a4400a99076898d010000b200000003eeb98ec44dad99796b79b0657bf94d22bfa669328dcd49d426ec60a3193f7c74cb4e28c75b832e00280e2db2e6f183e9744905c7ded4507c8063ce170104000000000118c0654e5cf9b188e197229a7bca0be3e5a5df710000a47f3a8f9e15021d228c10b01dbffe71e96c6fee010134b07fd87831a60c376eff6dffa1b53de5a384f90101e2a2b18869cd218db8e307d8d0907642279513a3c7c2121a0f94aacb40116488020daba9095f6f7689b4346002a99076898d0100000037f60a13dd093d403c340ef42fd7dd3635e7556bfbc2c17695c5af13f9933dd6011500000074785f696e69745f70726f706f73616c2e7761736d01a89123149f6f0fd600d82cc2d9e7c5ec5b8fc071b5f21d4f355d6080f6bd488d9326f493115e2d0ceb0107000000395f5f6c5f5235', 'hex'),
    sectionHashes: {
      0: Buffer.from('fe2b3b1736cf1f61b150aa3261bba8c12dedc1e787d7d27d6dab42871736cad6', 'hex'),
      1: Buffer.from('796b79b0657bf94d22bfa669328dcd49d426ec60a3193f7c74cb4e28c75b832e', 'hex'),
      2: Buffer.from('a9b2900ad8b2bff46678176d5579cfe068f6b9575ca6a877da4385220e548560', 'hex'),
      3: Buffer.from('1b4a30e7603606f68aa56abf4bfa2e2895c19027e1f81ed6f8c5ad1255a2302b', 'hex'),
      4: Buffer.from('57c6004e1684170da337d4209e7b3eab69ff44bbe92c7286b6a9ec263add247d', 'hex'),
      0xff: Buffer.from('d8eddc341d2dcaa4d424d930c6e7360e0e5ab04aef71153328c75fa6e30ef24e', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'update_vp',
    blob: Buffer.from('010000003101260000002d3138393235352d30392d32385432313a35383a35342e3531353039373133342b30303a3030260000002b3133363032392d30332d32355432313a30333a35372e3932363432323036382b30303a303090ff4ed48f5dbad61c94821e1e8103533ad93c87f0f73a736a7507ddbe443b05c8f771592526f205a5b08a5d7d762acf847e7eb42a447bca4aba6471a8d98ac57bb9560064a1b2f26570b2767407ed13f06371e69464060d54631abb4142ab270162f3ac36bf439508000000000000000000000000000000000000000000000000f3001759e8da89db2f0db7ceee4f6e8861f28561e7f20077e08552c0b502f26167f3de86fdfd7025c9b3dcbfdeb078bee3a3596dcf6b2c86beb30c962f840a3480cb145ab2444d000400000001b6af2b81b958e936001a74a1b82ae9856ccc19224615f6d463356a3c446e736c974aeaf9f17441a3590000ab9076898d0100007f00000000984b983297541d6f33d64dd5ab61fa4a95a11c78016b565afe9a6fd7dab8453d6219fdb02fcaca171898cbf43ca356493961fa95770200000001026c4af6c5d737180f7a9e4684a5724c4e70a0b1c24401c7de9d716c62a9f2f68d00621434b41e175caa4a04979f051c6af7c7dc1876cd733ec688f6d9be2619c7fe010002ab9076898d01000000ae00541ba3330250f7add0634fb53473a9f22b6917f8e852f514b3ce8d561d4b011600000074785f7570646174655f6163636f756e742e7761736d013e63339da161339f008929796a902b190423e944a40901ffe2a218c7b219356beed75f6001471ef62000', 'hex'),
    sectionHashes: {
      0: Buffer.from('0468327d8e7626c00e3ddbb30bc4d572049e11ae1e66f15ea557e40f67bd9381', 'hex'),
      1: Buffer.from('6b565afe9a6fd7dab8453d6219fdb02fcaca171898cbf43ca356493961fa9577', 'hex'),
      2: Buffer.from('c8f771592526f205a5b08a5d7d762acf847e7eb42a447bca4aba6471a8d98ac5', 'hex'),
      3: Buffer.from('90ff4ed48f5dbad61c94821e1e8103533ad93c87f0f73a736a7507ddbe443b05', 'hex'),
      4: Buffer.from('7bb9560064a1b2f26570b2767407ed13f06371e69464060d54631abb4142ab27', 'hex'),
      0xff: Buffer.from('5ebd2bb7e79b9d749d688c18f4fe22b3edba441bb92a0401400d7ac938a3cc45', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_pubkeys',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a31322e3030383437393437392b30303a303029e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca0048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80300000000000000a861000000000000000400000002b3078bd88b010000007c7a739c83e943d4a56a0fd4e4c52a9edc0d66d9105324bcc909619857a6683b010c00000074785f626f6e642e7761736d00b3078bd88b0100004b00000000f2d1fbf5a690f8ab12cfa6166425bec4d7569bb400e9a435000000000000000000000000000000000000000000000000000000000100ba4c9645a23343896227110a902af84e7b4a4bb30301000000c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e00000ba4c9645a23343896227110a902af84e7b4a4bb301000000000087d6e5a4617cce4c93120504a5f5db8c9ce1af0416e260c3fbe9066df3f3fdb2abfda0cac21b97b3e89b3c29013db345bd22548e8baf2df4e682bb4e1a041f0f03040000005b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b296501374229e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897bed4bfd3e247c0ef6e2ab23983a793412fd94a78d9a08efaa94a3d6a977e3c601c01010000000048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d8010000000000cfcc82f327627fed72368dd168663db755478675d812365b9c8b92c36acaaebf1fe9a0494aaf9e675d4b4f041ffebc5234d9da012721b1bd5d1bbc819ed56f04', 'hex'),
    sectionHashes: {
      0: Buffer.from('5b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b2965013742', 'hex'),
      1: Buffer.from('29e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58', 'hex'),
      2: Buffer.from('f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be', 'hex'),
      3: Buffer.from('d4bfd3e247c0ef6e2ab23983a793412fd94a78d9a08efaa94a3d6a977e3c601c', 'hex'),
      4: Buffer.from('ea7dd39da3e99c29ee2c51d7bc7cd14754010fa16531ff807988c5018fcccea4', 'hex'),
      0xff: Buffer.from('c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e0', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_address',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a31322e3030383437393437392b30303a303029e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca0048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80300000000000000a861000000000000000300000002b3078bd88b010000007c7a739c83e943d4a56a0fd4e4c52a9edc0d66d9105324bcc909619857a6683b010c00000074785f626f6e642e7761736d00b3078bd88b0100004b00000000f2d1fbf5a690f8ab12cfa6166425bec4d7569bb400e9a435000000000000000000000000000000000000000000000000000000000100ba4c9645a23343896227110a902af84e7b4a4bb30301000000c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e00001ed03655318474529449ed5f0bd81d2cbfa41d57a010000000000682203cfc3d10fd4bd2fbf57181012ca8f113e0b11ae6cd50621a2acf34e83b755fed6eeeb9f6f1c4f55765e2999ce8bd505fb48845e5f810ad57673fcb38e0d', 'hex'),
    sectionHashes: {
      0: Buffer.from('5b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b2965013742', 'hex'),
      1: Buffer.from('29e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58', 'hex'),
      2: Buffer.from('f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be', 'hex'),
      3: Buffer.from('d05ef8971a0464a35ab4d08efea23d6c9c86aeeb5e1e6992956ed814d0a3d761', 'hex'),
      0xff: Buffer.from('c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e0', 'hex'),
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
