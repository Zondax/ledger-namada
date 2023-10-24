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
    blob: Buffer.from('1e0000006532652d746573742e3938363263623234306665643035323030383263360023000000323032332d31302d32305431343a32313a30362e3532363835333934312b30303a3030a71a670335845fa05879bc8a8b16ab60fdea9d64c836f09e6360d6390f5b0bf64b04a6f5687ea495b87d8406414bc9cc8c34760d0988351d47cda2f0d04458f4010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60048d8fdf282dc3c916abf377b8700610ce297ba69492c5cb7f464eb60b3555bd30000000000000000204e0000000000000002000000028916764d8b01000000ad42b536c7238f79a3e641b66741584266cb332162819b8c2319e2f92cbe6d9a008916764d8b0100004b000000007587ca955e444977af143b0f98520609420d927a00e9a43500000000000000000000000000000000000000000000000000000000010025bdd85cae88305e4ee8dde13441c9fa43f72450', 'hex'),
    // Ordered sections hashes (code, data, extraData)
    sectionHashes: [
      Buffer.from('a71a670335845fa05879bc8a8b16ab60fdea9d64c836f09e6360d6390f5b0bf6', 'hex'),
      Buffer.from('4b04a6f5687ea495b87d8406414bc9cc8c34760d0988351d47cda2f0d04458f4', 'hex'),
    ],
    headerHash: Buffer.from('446b6a8f1aec8beee01a04615fb79e1cdf716f73241aac6104fc5f46dde127f1', 'hex'),
    signatureHashes: undefined
  },
  {
    name: 'init_account',
    blob: Buffer.from('1e0000006532652d746573742e3938363263623234306665643035323030383263360023000000323032332d31302d32305431343a32323a35372e3632393637333330362b30303a303063cf4667aa201e3eff58e33fbe2cf968c341b802a7f038c8166c4eba6bb699c0a5ba4178649244238d9c225f3f3658c1ae2e8606ba6ed4ab3d933e3a55f833e8010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6002550ab13d40e1de991910dd01c660500caaf3329f77e1aec0009bf1774bbd4b40100000000000000204e00000000000000030000000189c8774d8b0100000072d2c2b9fc247ce6cd6ac00bb5bccc3569d0b94b01af746fb3b4ce48761060d30289c8774d8b0100000050cb32298b6f6bbd661e09d36bbe7ba7ce2c9db75392a9879ae7381e87c9fc3a0089c8774d8b0100004600000001000000002550ab13d40e1de991910dd01c660500caaf3329f77e1aec0009bf1774bbd4b4599ea1dfa040d88701450daa24b50b5dcf5fa1751dfa36d7bd28aaec8395ffd801', 'hex'),
    sectionHashes: [
      Buffer.from('63cf4667aa201e3eff58e33fbe2cf968c341b802a7f038c8166c4eba6bb699c0', 'hex'),
      Buffer.from('a5ba4178649244238d9c225f3f3658c1ae2e8606ba6ed4ab3d933e3a55f833e8', 'hex'),
      Buffer.from('599ea1dfa040d88701450daa24b50b5dcf5fa1751dfa36d7bd28aaec8395ffd8', 'hex'),
    ],
    headerHash: Buffer.from('1c4a6cbc3a9935aca6c08a2dcdf3ababe92ea81392b532db10fd4ae69ddc2340', 'hex'),
    signatureHashes: undefined
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1e0000006532652d746573742e3938363263623234306665643035323030383263360023000000323032332d31302d32305431343a32313a32302e3335373337343034312b30303a3030288b5a03bc5c388371bea05e6100c5ecac954474baca07a11ff5b70455bd975891bf3ae9d11e5fe20b10e96d6cf85e6f097885e6dcd28fbe02edd125c6b383be010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6002550ab13d40e1de991910dd01c660500caaf3329f77e1aec0009bf1774bbd4b40100000000000000204e000000000000000300000001904c764d8b010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e02904c764d8b01000000d1baa37345ffdb850c6b092f5b314ff04125dfb530f11eadb3a866da9078b36f00904c764d8b0100005000000000d822bdbfc143a16647adef4cec1338a5323a736cc8df87c0a6a065080f1f2eb5009e88a04ca1c94668de92f4ccfe00c276b067ef8100000c0000000000000018000000000000001e00000000000000', 'hex'),
    sectionHashes: [
      Buffer.from('288b5a03bc5c388371bea05e6100c5ecac954474baca07a11ff5b70455bd9758', 'hex'),
      Buffer.from('91bf3ae9d11e5fe20b10e96d6cf85e6f097885e6dcd28fbe02edd125c6b383be', 'hex'),
      Buffer.from('d822bdbfc143a16647adef4cec1338a5323a736cc8df87c0a6a065080f1f2eb5', 'hex'),
      ],
      headerHash: Buffer.from('9382ec4afc1281a38ff6db77fa20be22f9b73526fef5187d2334a2c78cdfe8a2', 'hex'),
      signatureHashes: undefined
  },
  {
    name: 'init_validator',
    blob: Buffer.from('1e0000006532652d746573742e3938363263623234306665643035323030383263360023000000323032332d31302d32305431343a32323a34322e3234363833373434392b30303a3030a44087911faffb21c79da1bd1b52d72d412f47fd5bbd66c5de66922472f68bf0c32fc84d2f7437914e1fadc942a163c07bfe4eea2017a33b0469d485d522128f010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60048d8fdf282dc3c916abf377b8700610ce297ba69492c5cb7f464eb60b3555bd30100000000000000204e000000000000000300000001468c774d8b0100000072d2c2b9fc247ce6cd6ac00bb5bccc3569d0b94b01af746fb3b4ce48761060d302478c774d8b010000009446a4fc34b67b48c15bbb3ebde3a52500306b6999ccb043a0fe130eec63f1f100478c774d8b0100006e010000010000000048d8fdf282dc3c916abf377b8700610ce297ba69492c5cb7f464eb60b3555bd30100434a001d9695cba3a70f03cbeaf408c5da1851abd2462053b9275be3d73980e603cc91740f9a5c102da78164f32e41e2a597ed0db096354d84572820e3f5ebe2ed02bd061edde6168185878fbc7d59fc6f67193fb3b340ee55212bf1a0c04436a0f300440779f43f9c641ef4ca1138ceafd61931d439429a0e20c060cf989d819cec0560000000f2a9f1a8090d3794e036e4a2de506bc40cb76b8b8fc2d19ef85fc2aacec9e2bf96ff0e52c64d4cfdadb9329edc4d310bff2b63c44371e5c34372fb758921a408e112f47420150a7d4788594396bd14584c082f95b175cd2ff169af95bc9e5a9200743ba40b00000000000000000000000000000000000000000000000000000000e40b540200000000000000000000000000000000000000000000000000000076296c42003075b5d241c87fa7fe90c25aba4c4c7d4d22d4778d3905e1882973', 'hex'),
    sectionHashes: [
      Buffer.from('a44087911faffb21c79da1bd1b52d72d412f47fd5bbd66c5de66922472f68bf0', 'hex'),
      Buffer.from('c32fc84d2f7437914e1fadc942a163c07bfe4eea2017a33b0469d485d522128f', 'hex'),
      Buffer.from('76296c42003075b5d241c87fa7fe90c25aba4c4c7d4d22d4778d3905e1882973', 'hex'),
    ],
    headerHash: Buffer.from('53a18f4ef4c07258bc07a26c3639b7894b798a47fd1cabf5f3d04329f44d078c', 'hex'),
    signatureHashes: undefined
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1e0000006532652d746573742e3938363263623234306665643035323030383263360023000000323032332d31302d32305431343a32323a33302e3438363535333236342b30303a3030c65925533e8569446bf821a239c159f82520a4089677fe4064f0d8b3ac8b4081309b0cdf4cd79b698a3c4ae5577f2237900cb370fd157464d21823b9f020b7ec010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60048d8fdf282dc3c916abf377b8700610ce297ba69492c5cb7f464eb60b3555bd30100000000000000204e000000000000000300000001815e774d8b0100000072d2c2b9fc247ce6cd6ac00bb5bccc3569d0b94b01af746fb3b4ce48761060d302815e774d8b01000000d744059f698888fb5f4b96f531fe5e2f1eb307ed52621ccc189bbf022ae36ad500815e774d8b0100003b0000000025bdd85cae88305e4ee8dde13441c9fa43f7245001e16fa335bffca2c7a23449168b22d68546ba5e7b7cd7fd3851147c44054ebf320000000000', 'hex'),
    sectionHashes: [
      Buffer.from('c65925533e8569446bf821a239c159f82520a4089677fe4064f0d8b3ac8b4081', 'hex'),
      Buffer.from('309b0cdf4cd79b698a3c4ae5577f2237900cb370fd157464d21823b9f020b7ec', 'hex'),
      Buffer.from('e16fa335bffca2c7a23449168b22d68546ba5e7b7cd7fd3851147c44054ebf32', 'hex'),
    ],
    headerHash: Buffer.from('8f76ff201a5bfad6ce779505d0a6ee2370c3914249c7b5ea3d11db21bf8a6fe0', 'hex'),
    signatureHashes: undefined
  },
  // {
  //   name: 'multisig',
  //   blob: Buffer.from('1e0000006532652d746573742e3234393263633931333335643832326331336637390023000000323032332d30392d31345430383a34313a30322e3836303736363630382b30303a303011db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882ccae4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6008cc3af30ba637b5d68a9e216541a67b4779601e7a83881e52ed58bad1ef129ea0100000000000000204e00000000000000000500000001bed0d9928a010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e01bed0d9928a01000000deb9a0d7a7b7752ae34cde5a3ec9fcb6b6780f2351f3eda92dcf07c4a9666e9802c7d0d9928a0100000046844bfdbb8bfbbf44bd4eafb7cd25466631b2adf19e3ba769fe46fd52f1825700c7d0d9928a01000070000000008737ea6fafa74870269d6d10baf77b490c9e5eba70ba194a6bbd00cf145594f60000e7368e1eacc4c61482441079c0e0d75b5b70b900013918de0c8871747490e75053550f4b6c8d6939b71ce316bb53f6608558ff97950c0000000000000018000000000000001e00000000000000030200000011db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882ccae4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2010100000000d2bbc65a45539c4dc73fd03f896616e56ec326ae8e7f9de08bd4efcc3a506cb8010000000000b27260f8da5c03b7f54a54430d018c9b044ba39957d59db35db483ff0f83cc0a4dfca76341421b439d0434ae012af0806de469487fb866b28c0a01cc7184f30c', 'hex'),
  //   sectionHashes: [
  //     Buffer.from('11db58130f36c86cdbe872c396158aa4d0792ec824237df6c6be8fa9e7882cca', 'hex'),
  //     Buffer.from('e4d9a0695da3d772008b5ac0b77a55350c9d8380b2d5418016b7200f29af42b2', 'hex'),
  //     Buffer.from('8737ea6fafa74870269d6d10baf77b490c9e5eba70ba194a6bbd00cf145594f6', 'hex'),
  //     Buffer.from('3918de0c8871747490e75053550f4b6c8d6939b71ce316bb53f6608558ff9795', 'hex'),
  //   ],
  //   headerHash: Buffer.from('4a91ed080e8fae63e8ca0f34fbe8d4f86c47022d8a45e0bedc3b6c7abaf12927', 'hex'),
  //   signatureHashes: Buffer.from('4ca0aca5228a1bc0fd295b971f63369e618d5ff7df77664ace61668bd95fee9d', 'hex')
  // },
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
