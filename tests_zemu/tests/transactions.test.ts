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


function hashSignatureSec(pubkeys: Buffer[], salt: Buffer, hashes: Buffer[], signature: Buffer | null, prefix: Uint8Array | null) {
  let hash = sha256.create();
  if (prefix != null) {
    hash.update(prefix);
  }

  // Hashes
  hash.update(new Uint8Array([hashes.length, 0, 0, 0]));
  for (let i = 0; i < (hashes.length); i ++) {
    // Hashes must be ordered
    hash.update(Buffer.from(hashes[i]));
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
    blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34303a34372e3833303431303837312b30303a3030f7f8169f3013bb79e82fe718adaebb7eaa31ce88f535b81fb76d14880387871a2e81200c63c437224371396d094864f6d98dca88db85c8ea53edd3794a8401a5010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600044c369af7ca5d8cb01c4168699d8c1d4ee3ef8866a0b36ab81b9a5168780ec50100000000000000204e000000000000000002000000020296d9928a01000000a45305b1984005309b77d5d7125f15436cc0d6397839bc74210877363a978b3c000296d9928a0100004b00000000c13dc996a7b6f11772f66e2e0fcaf0e21780008900e9a435000000000000000000000000000000000000000000000000000000000100647aea12a9f1eee39f82dd30cef514f4ea1a49b0', 'hex'),
    // Ordered sections hashes (code, data, extraData)
    sectionHashes: [
      Buffer.from('f7f8169f3013bb79e82fe718adaebb7eaa31ce88f535b81fb76d14880387871a', 'hex'),
      Buffer.from('2e81200c63c437224371396d094864f6d98dca88db85c8ea53edd3794a8401a5', 'hex'),
    ],
    headerHash: Buffer.from('b18d30a556f0e2cf783134bd74df96b21e44a25e90eef3c3a15ec332c6a93a9a', 'hex'),
  },
  {
    name: 'init_account',
    blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34323a34322e3033333430363838382b30303a3030f9cb136a4d542151266776df8f176661940ea5d1ba4fcff8945aeffd4a8c1104c4be9dbe881d5c637649d47ef5c477d0ab6bd6e4fcd9279a0aaef6a9764d0d8d010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea0100000000000000204e000000000000000003000000011e54db928a010000001c05c88ecb42362753e672db473770bb46b5685449d810cf407bde68d906f08c021e54db928a01000000f13534a21b8afd058e4e64366961bd5864864956cc915a745ad3cc087eb0a6d7001e54db928a0100008800000003000000008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea00044c369af7ca5d8cb01c4168699d8c1d4ee3ef8866a0b36ab81b9a5168780ec500b126f531259fc6477f69b654202e9ef30ff21719024393463350286a2fbfd30719dda621df14473df5c1b2b0c0ade265cd0c27132f3b1ba4c8bca26d4389c99502', 'hex'),
    sectionHashes: [
      Buffer.from('f9cb136a4d542151266776df8f176661940ea5d1ba4fcff8945aeffd4a8c1104', 'hex'),
      Buffer.from('c4be9dbe881d5c637649d47ef5c477d0ab6bd6e4fcd9279a0aaef6a9764d0d8d', 'hex'),
      Buffer.from('19dda621df14473df5c1b2b0c0ade265cd0c27132f3b1ba4c8bca26d4389c995', 'hex'),
    ],
    headerHash: Buffer.from('8efe673b496344b1bbc14dd4f48036fbf505d5a71968c919b9629991161c71ff', 'hex'),
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34313a30322e3836303736363630382b30303a303011db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882ccae4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea0100000000000000204e00000000000000000400000001bed0d9928a010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e01bed0d9928a01000000deb9a0d7a7b7752ae34cde5a3ec9fcb6b6780f2351f3eda92dcf07c4a9666e9802c7d0d9928a0100000046844bfdbb8bfbbf44bd4eafb7cd25466631b2adf19e3ba769fe46fd52f1825700c7d0d9928a01000070000000008737ea6fafa74870269d6d10baf77b490c9e5eba70ba194a6bbd00cf145594f60000e7368e1eacc4c61482441079c0e0d75b5b70b900013918de0c8871747490e75053550f4b6c8d6939b71ce316bb53f6608558ff97950c0000000000000018000000000000001e00000000000000', 'hex'),
    sectionHashes: [
      Buffer.from('11db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882cca', 'hex'),
      Buffer.from('e4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2', 'hex'),
      Buffer.from('8737ea6fafa74870269d6d10baf77b490c9e5eba70ba194a6bbd00cf145594f6', 'hex'),
      Buffer.from('3918de0c8871747490e75053550f4b6c8d6939b71ce316bb53f6608558ff9795', 'hex'),
      ],
      headerHash: Buffer.from('4a91ed080e8fae63e8ca0f34fbe8d4f86c47022d8a45e0bedc3b6c7abaf12927', 'hex'),
  },
  {
    name: 'init_validator',
    blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34323a32362e3831303736303036372b30303a30302698eb51dd56700b79409292d94c35aff2197ff212ee06d64bc11cb0519f43b0be530615d7d1e194c49a897768f213ad4241dbdbfb2d0793993dff41b8da5d58010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea0100000000000000204e000000000000000003000000017a18db928a010000001c05c88ecb42362753e672db473770bb46b5685449d810cf407bde68d906f08c027b18db928a01000000bec486bb8ca3ddc54019ee0b8f65849ec1f886e515c65e85a006233412fd9aac007b18db928a0100008f01000002000000008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea00044c369af7ca5d8cb01c4168699d8c1d4ee3ef8866a0b36ab81b9a5168780ec5020023cf31063138dd5a79d2b5b1090d7215770bfbd2411a53507bd1bf7dfe3ef20b02caf63502eacf0cad3aac4dcbdb47722d82bc4c0a51c29985f433cafbec0e6add0370fbc7ba643dc570ffc62e57f32c56e76a9ca2bd51c6e66e3007bf9b642cc09f0018d1290b0eb97b22c474a4b0591a311743dcc3426d1c8a8392a8b17ed443b4f0600000006649a086526afc1169e08259c4f998c3a1e7949d56446eee1db4f3fd9001afa9d1c4a601b9972c874aa1afe85b4db218d736320847ef52e51942e8780bf8f0a7557c11812399fd17e347a71219f20f2686321ebd2504f3665b1849474e93918e00743ba40b00000000000000000000000000000000000000000000000000000000e40b5402000000000000000000000000000000000000000000000000000000ac04ad1fcf88098226c522f1f51dec357731f4ede1c6f933d8160968772f764b', 'hex'),
    sectionHashes: [
      Buffer.from('2698eb51dd56700b79409292d94c35aff2197ff212ee06d64bc11cb0519f43b0', 'hex'),
      Buffer.from('be530615d7d1e194c49a897768f213ad4241dbdbfb2d0793993dff41b8da5d58', 'hex'),
      Buffer.from('ac04ad1fcf88098226c522f1f51dec357731f4ede1c6f933d8160968772f764b', 'hex'),
    ],
    headerHash: Buffer.from('1166ce0d915e2d362c3d90e635cafab3beaaad39c490684473dacc7ee0d01b38', 'hex'),
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34323a31392e3830323834313831322b30303a303054f6d48f2a802e1252118580fefc3554a8293f5e3420769f66c7c81cf506677aaa7a81cf08c4b19d3c91f143649d2f428c3d34b9348f38a39d877c229f5aef89010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea0100000000000000204e0000000000000000030000000146fdda928a010000001c05c88ecb42362753e672db473770bb46b5685449d810cf407bde68d906f08c0246fdda928a010000007b53a6bb499a183eb9e42da2b9a7e3296303706f211c796d60d1476bea7062500046fdda928a0100009f00000000647aea12a9f1eee39f82dd30cef514f4ea1a49b0018fb861bbdf50f9a196239fb61d36ec1b1320ecaf292c020b54d0add821bdc01403000000008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea00044c369af7ca5d8cb01c4168699d8c1d4ee3ef8866a0b36ab81b9a5168780ec500b126f531259fc6477f69b654202e9ef30ff21719024393463350286a2fbfd3070102', 'hex'),
    sectionHashes: [
      Buffer.from('54f6d48f2a802e1252118580fefc3554a8293f5e3420769f66c7c81cf506677a', 'hex'),
      Buffer.from('aa7a81cf08c4b19d3c91f143649d2f428c3d34b9348f38a39d877c229f5aef89', 'hex'),
      Buffer.from('8fb861bbdf50f9a196239fb61d36ec1b1320ecaf292c020b54d0add821bdc014', 'hex'),
    ],
    headerHash: Buffer.from('20a62e73d43ce617d99f10207cd6600b00bb3f0a5ab16fbd430c4fdb0713d1bb', 'hex'),
  },
  {
    name: 'multisig',
    blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34313a30322e3836303736363630382b30303a303011db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882ccae4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea0100000000000000204e00000000000000000500000001bed0d9928a010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e01bed0d9928a01000000deb9a0d7a7b7752ae34cde5a3ec9fcb6b6780f2351f3eda92dcf07c4a9666e9802c7d0d9928a0100000046844bfdbb8bfbbf44bd4eafb7cd25466631b2adf19e3ba769fe46fd52f1825700c7d0d9928a01000070000000008737ea6fafa74870269d6d10baf77b490c9e5eba70ba194a6bbd00cf145594f60000e7368e1eacc4c61482441079c0e0d75b5b70b900013918de0c8871747490e75053550f4b6c8d6939b71ce316bb53f6608558ff97950c0000000000000018000000000000001e00000000000000030200000011db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882ccae4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2010100000000d2bbc65a45539c4dc73fd03f896616e56ec326ae8e7f9de08bd4efcc3a506cb8010000000000b27260f8da5c03b7f54a54430d018c9b044ba39957d59db35db483ff0f83cc0a4dfca76341421b439d0434ae012af0806de469487fb866b28c0a01cc7184f30c', 'hex'),
    sectionHashes: [
      Buffer.from('11db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882cca', 'hex'),
      Buffer.from('e4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2', 'hex'),
      Buffer.from('8737ea6fafa74870269d6d10baf77b490c9e5eba70ba194a6bbd00cf145594f6', 'hex'),
      Buffer.from('3918de0c8871747490e75053550f4b6c8d6939b71ce316bb53f6608558ff9795', 'hex'),
    ],
    headerHash: Buffer.from('4a91ed080e8fae63e8ca0f34fbe8d4f86c47022d8a45e0bedc3b6c7abaf12927', 'hex'),
    signatureHashes: Buffer.from('4ca0aca5228a1bc0fd295b971f63369e618d5ff7df77664ace61668bd95fee9d', 'hex')
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
      const unsignedRawSigHash = hashSignatureSec([], signature.raw_salt, data.sectionHashes, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.pubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03]);
      const rawHash: Buffer = hashSignatureSec([signature.pubkey], signature.raw_salt, data.sectionHashes, signature.raw_signature, prefix);

      const tmpHashes: Buffer[] = data.sectionHashes.concat([rawHash, data.headerHash]);
      if (data.signatureHashes !== undefined) {
        tmpHashes.push(data.signatureHashes)
      }

      const unsignedWrapperSigHash = hashSignatureSec([], signature.wrapper_salt, tmpHashes, null, null);
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.publicKey.subarray(1));

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
