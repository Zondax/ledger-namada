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


function hashSignatureSec(pubkey: Buffer, salt: Buffer, hashes: Buffer[], signature: Buffer | null, prefix: Uint8Array | null) {
  let hash = sha256.create();
  if (prefix != null) {
    hash.update(prefix);
  }
  hash.update(salt);
  hash.update(new Uint8Array([hashes.length, 0, 0, 0]));
  for (let i = 0; i < (hashes.length); i ++) {
    // Hashes must be ordered
    hash.update(Buffer.from(hashes[i]));
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
    blob: Buffer.from('1e0000006532652d746573742e6161386333633535623134626665393237626236380023000000323032332d30372d31345430363a34333a30382e3233363639313239372b30303a30302084db3e29d0b37134355bfaf2c6ba2416ea9781206e62f289bee1090b739d0a6d62bdae7cf3538118476cfc54bbb217134e6241f202fec7b70f8fa30a045a7d0100e1f50500000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600d02e8499653b2e032de872b87ff31b1997ccf141280b762f95eb9884a047ab6c010000000000000000000000000000000000000000000000000000000000000000000000000000000002000000004c952353890100004b000000008150ac44e37aa6813a91a39cc2ae23e37cf8ae6600e9a435000000000000000000000000000000000000000000000000000000000100e1cc098a43e19c889b18781b3f50d9425bbba64f024c9523538901000000f44f821502b1d8ef3bb11af645babe350394c39c6b8b1cef848bf60aa4aaaf8d', 'hex'),
    // Ordered sections hashes (code, data, extraData)
    sectionHashes: [
      Buffer.from('2084db3e29d0b37134355bfaf2c6ba2416ea9781206e62f289bee1090b739d0a', 'hex'),
      Buffer.from('6d62bdae7cf3538118476cfc54bbb217134e6241f202fec7b70f8fa30a045a7d', 'hex'),
    ],
    headerHash: Buffer.from('77f154b96b7180b54617ebb5a336df77fe43becca67b357ff11879836667124b', 'hex'),
  },
  {
    name: 'init_account',
    blob: Buffer.from('1e0000006532652d746573742e6162356634653963613731623732316437383830350023000000323032332d30372d31345431303a34393a34382e3536343330333436362b30303a30303dce2504370b8c68e4145eb7d3b7fa82779dfc13fd3e51b41a8267fe6f0faf1e74f7846ab5a0a81258a3659591db36532c51a1bb50bdd78ea0961639b9729c5e0100e1f50500000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60034ea3e9f341e241a4836e6a903553c04bd3274f9cafda91a47a263adefe998bc02000000000000000000000000000000000000000000000000000000000000000000000000000000010108000000000000003c010000000000000300000001146b055489010000002451515c3a6fa063eb25d90ef15268dfbdd37133521c34fb58b68b1c4b61918000146b055489010000410000000034ea3e9f341e241a4836e6a903553c04bd3274f9cafda91a47a263adefe998bc1c12c326aba059d7f328a2b067c9267c30b7d5ece73d117bb9708ceaafb73dcc02146b0554890100000039c4f8d4e9b14aac4491d115fa5d4382be490ac9b5bf6d191f8aa66fa4e12bf6', 'hex'),
    sectionHashes: [
      Buffer.from('3dce2504370b8c68e4145eb7d3b7fa82779dfc13fd3e51b41a8267fe6f0faf1e', 'hex'),
      Buffer.from('74f7846ab5a0a81258a3659591db36532c51a1bb50bdd78ea0961639b9729c5e', 'hex'),
      Buffer.from('1c12c326aba059d7f328a2b067c9267c30b7d5ece73d117bb9708ceaafb73dcc', 'hex'),
    ],
    headerHash: Buffer.from('9ae2e2b357029119a343ddbc1411a8d17238eb6cee4d78a8e5ef9377b568fb92', 'hex'),
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1e0000006532652d746573742e3532373439376562383436323765626161323136300023000000323032332d30372d31375431303a32313a35312e3833313032373534382b30303a30306a8eb3d84b2740af823ed1a7958585ea60ba2ef94490e6a4572d2b97a50da451623c31e0e73a7d2910e37feabacacea39ba6cf588996f642aa294d772b19a7300100e1f50500000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600e81ad37eb0fd99f80955d99aeafbef1964d2598207d094703708ba2e93d76b760100000000000000000000000000000000000000000000000000000000000000000000000000000000040000000184e95e6389010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e0184e95e6389010000000c81a357320d8d093ab99792a92af4c0fe7e9ac010199a5e85d41cc89c331e8f009be95e638901000070000000007d5f7b1d00e9a557fbe7d80113fdb0ae9ce0f8b76886738081b1c21372b70e6600b298f6fea31c74f0ccb6aad7d67b881e7c98fa940001955c283a32d1b70d6d6a251b10060eca456c156e9c376f3708f6961a7da3ad6d0c0000000000000018000000000000001e00000000000000029be95e638901000000d0a4d681cdc8b83e04a64fbc592bcbe9d93f28164d2d5cb5ff9a4fbd43d206b8', 'hex'),
    sectionHashes: [
        Buffer.from('6a8eb3d84b2740af823ed1a7958585ea60ba2ef94490e6a4572d2b97a50da451', 'hex'),
        Buffer.from('623c31e0e73a7d2910e37feabacacea39ba6cf588996f642aa294d772b19a730', 'hex'),
        Buffer.from('7d5f7b1d00e9a557fbe7d80113fdb0ae9ce0f8b76886738081b1c21372b70e66', 'hex'),
        Buffer.from('955c283a32d1b70d6d6a251b10060eca456c156e9c376f3708f6961a7da3ad6d', 'hex'),
      ],
      headerHash: Buffer.from('50999a33a75fd042f088cb7eb8d9e0a16cbaa429c6f19ab47a6a760f6e9a6bb0', 'hex'),
  },
  {
    name: 'init_validator',
    blob: Buffer.from('1e0000006532652d746573742e3532373439376562383436323765626161323136300023000000323032332d30372d31375431303a32333a30372e3538313931353932362b30303a3030145e646087e95106c9df43aa377ae656a3e516ec20d87bdfa8afe51a857a845a52e9300343ff739df098ae4b4d5a852c0aad4c43bb29f157bb2a8e48f76743ac0100e1f50500000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e6007930887c08f82ce6d2af627346a6af7fbbd823b22ebe13087e89ccff9d5607d9010000000000000000000000000000000000000000000000000000000000000000000000000000000003000000013d11606389010000002451515c3a6fa063eb25d90ef15268dfbdd37133521c34fb58b68b1c4b619180003e1160638901000027010000005c147798f1b4c4aaa8e93660d26f8a423359b359ac34012337ab49ec909fe23500436ae38a978f5085d795c9bc42cd14c47e4cfbd4eb3f8032f1e58a5f92903bb600e3600ab2d095a2ecaba80635869e6a3f04a8fd34a118a72bcad4ccb606d981a360000000490404842d4af404356b141de81539329b6a3051e3bd3002752539ef6555d58e5f137268034cc0795ab58f052843510ba789396a42148564e55da4a726b5796ee82e5bc276478de0d4d7f0e5140b63aaf95b5217203e043bb191e05409daf60400743ba40b00000000000000000000000000000000000000000000000000000000e40b540200000000000000000000000000000000000000000000000000000074809b5b1bf1e8172423405702ff19d6fed93f4fab33fd852dcf3428ae683e7b023e1160638901000000e54eb11bed86e57e6888a70ef4d2705034b42fcc7dd4c1314a49f59dc004e497', 'hex'),
    sectionHashes: [
      Buffer.from('145e646087e95106c9df43aa377ae656a3e516ec20d87bdfa8afe51a857a845a', 'hex'),
      Buffer.from('52e9300343ff739df098ae4b4d5a852c0aad4c43bb29f157bb2a8e48f76743ac', 'hex'),
      Buffer.from('74809b5b1bf1e8172423405702ff19d6fed93f4fab33fd852dcf3428ae683e7b', 'hex'),
    ],
    headerHash: Buffer.from('990e551f88a4ab9eb5b09f7ec9e0dfef5f7ec3ced9d2430e6be9b16806720827', 'hex'),
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1e0000006532652d746573742e3733653533353766356565333838373363336239660023000000323032332d30372d31375430393a31343a34342e3534393432383436352b30303a30309fd85611c72fa41189ea37d8ee6cdec80bd75fcca2993619572426cbf7b134f2c829e5fa0c7eb341bd2dd3a8f9bc4ae5bd184f87f88002390919fbee0c7c1cdf0100e1f50500000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60023e801289fcc5c551380b8d216f34d3b67d2a0d3e7a83b7f76fbf20b1bbef50501000000000000000000000000000000000000000000000000000000000000000000000000000000000300000001c575216389010000002451515c3a6fa063eb25d90ef15268dfbdd37133521c34fb58b68b1c4b61918000c5752163890100003500000000f564057b25c14f8f3ec4adc45153be688cd31a4b835a7f04d1df264515ac237d813a9cc1d7065a0e8e901395c4494f75bb771fa302c57521638901000000087de3038482e3cc0fd53c2bf5dd988b6a55a5507c271403a48b9456162b7cc7', 'hex'),
    sectionHashes: [
      Buffer.from('9fd85611c72fa41189ea37d8ee6cdec80bd75fcca2993619572426cbf7b134f2', 'hex'),
      Buffer.from('c829e5fa0c7eb341bd2dd3a8f9bc4ae5bd184f87f88002390919fbee0c7c1cdf', 'hex'),
      Buffer.from('835a7f04d1df264515ac237d813a9cc1d7065a0e8e901395c4494f75bb771fa3', 'hex'),
    ],
    headerHash: Buffer.from('092330b2e76bde0859970edabd74d307370a578ff70e2cfc0b6a45abe35c2669', 'hex'),
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
      const unsignedRawSigHash = hashSignatureSec(signature.pubkey, signature.raw_salt, data.sectionHashes, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.pubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03]);
      const rawHash: Buffer = hashSignatureSec(signature.pubkey, signature.raw_salt, data.sectionHashes, signature.raw_signature, prefix);
      const tmpHashes: Buffer[] = data.sectionHashes.concat([rawHash, data.headerHash]);
      const unsignedWrapperSigHash = hashSignatureSec(signature.pubkey, signature.wrapper_salt, tmpHashes, null, null);
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.publicKey.subarray(1));

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
