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
    blob: Buffer.from('150000005552355f5f325a61455f6e36326a4f54655973355f00260000002d3234333338352d30362d33305430343a34353a35302e3537313637353535362b30303a30306692c99f5c20a9b2031889db018bb6459e8c42203dafa62f8c019a9c4e4dbc62e6a825ebd04018efadd3d85c7b7c6055010ada9d12974a937ad34d7493c63445686829c655a91165cb9e70971ef887843ee5c0b31369141ac9ade456711a6cee01d1429a3798de6d23000000000000000000000000000000000000000000000000050031d10fd973261dd8a45ab446bf1912375ab85bda0062ca77b4ae3a84b582b6dcc2e385156de8d3b03a52c87f0c3a29beef54fb85b1eef44352e2f12d063e99624b3e2b151a016b13c950778aab52516b28c3bbd38ac0529bdcafd523de0339fb11e39afb9387020000000092fe73788d0100004b0000000007e0c2092d7266a53044324f00cdebb6fe3918c697a5727b3e091c240000000000000000000000000000000000000000000000000100bdb3ae7d368aace8b84940aa7dcdef116e06bfde0292fe73788d01000000e30fedce40816e3afc87c1b4a7c97b3e0c6b4627310d37d00d04cf87a6629653010c00000074785f626f6e642e7761736d', 'hex'),
    sectionHashes: {
      0: Buffer.from('c32ffdff6163484fe5feb04a6c8f747a4052c21945dcc7f12ca466868c4a4933', 'hex'),
      1: Buffer.from('e6a825ebd04018efadd3d85c7b7c6055010ada9d12974a937ad34d7493c63445', 'hex'),
      2: Buffer.from('6692c99f5c20a9b2031889db018bb6459e8c42203dafa62f8c019a9c4e4dbc62', 'hex'),
      0xff: Buffer.from('326289a26ecbe995affe03912a4e84b9c853262c01ef4924f31f3be22e7e1a1a', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('010000006501250000002d38383436322d31312d32325432303a34303a32382e3434393530343936302b30303a3030250000002d36363238312d30342d31305431323a33343a34362e3533373633393530392b30303a303084b50ff831bb0f36dd0d705ecbd847caaf14244ec95fe338b96461e31882a734b16b9f303355bc8166c3c309195d0fdaaca0eac4844ba6f6da3679a65c50eb675fb440bb17581ff8778657a0ab2afbe2e8c6996ff030eecaae1dc9d1e6a447890176fb615a472798e50000000000000000000000000000000000000000000000009100c274c2cecdd8c0dc49749891ac8cae7de5a1cec400ca2396199d3938b17d4614e0d189d5f84142dec9ed64f5530428f3af47731dfb742d172a2f58008c08925c13fa3883cc000300000001f15808a87019a12b006fa92d1c234068417b9d7fa5617afe11dc190a1a0c2ed0d5ef791cc8ca329fb90000d30bc5748d010000570000006ab46dded4bf9cf00559cf6e8f3794d5ad54b395128fb6bc6e68140a229855e675c7c4efac83f8f900325b2d09ccc34a103f055c63bb21dc25010c7be40000214155fb03c26cd7a8223ae6ae4500bd5239aa7f6319239602d30bc5748d010000007880578dc38af508fb6329948e196f43c756dc5932fa2a23022c69b54bfd5759011500000074785f696e69745f70726f706f73616c2e7761736d', 'hex'),
    sectionHashes: {
      0: Buffer.from('614410aa22ffd844182fa77e52d9889bf39e22b66ad2c6ce61d7e778588e51f2', 'hex'),
      1: Buffer.from('0559cf6e8f3794d5ad54b395128fb6bc6e68140a229855e675c7c4efac83f8f9', 'hex'),
      2: Buffer.from('b16b9f303355bc8166c3c309195d0fdaaca0eac4844ba6f6da3679a65c50eb67', 'hex'),
      3: Buffer.from('84b50ff831bb0f36dd0d705ecbd847caaf14244ec95fe338b96461e31882a734', 'hex'),
      0xff: Buffer.from('f5b5a6c176894fa5e624b549e4e7ccf5b442c20e8b37bc99374c083f7c02bbfa', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1e000000347133434953386c6e5f5f4e5657747a4d30587538545f30535f695f694601250000002b37323536322d31322d32385432313a34323a31312e3636393233393337382b30303a3030260000002b3236313437372d31312d30395430363a31373a35352e3637383136333537392b30303a30301016529e0f47127de7f27b40d479856e09d56b3b071fdfba740f70bcb13e9e8d0f0b2ab4a4b0c8037e5e4a69b57a161ad61725d9238da54e4f7aef83287f48bb478a1fdcac485929cf6cfb0eafcd994265f4220b76974c6e48e947fe235eb05501182b37fb0cad25500000000000000000000000000000000000000000000000005400e5b331e2bef7a2a64a901e85e3d1c7898efb37fa009edbe8da5a7d769490fa23cd647a5483ee4c3887d5b59cab66bdcf7380f27699e35715b47d9c02120d811502bfd124c101fb91884dd8240120b5d8afb36be277ff827f02c403454094f3e5032c0729464e0300000001884f57f60ff7b0de00af2b089e3aafdecc096bdca242dde6aff6ebc15ce4ba33045290f9c37f30a6dc0000d5fe73788d0100003c00000001d3ed6a7207e133c19c181f3a44008d319921616c01da73db72fa4425a4fab613f0005e8f7ef58d8df7ac671c81119189a498f84af300000000010002d5fe73788d01000000d9510e0f4e1fd123e9cf4033b5b3752eed07164e2e8a9e336b9dfdfe72b1f45a011600000074785f7570646174655f6163636f756e742e7761736d', 'hex'),
    sectionHashes: {
        0: Buffer.from('62471999b85604e0c74af0120b5ce29bfd0c0b2e26e219c0c12c8ebda17efb3f', 'hex'),
        1: Buffer.from('da73db72fa4425a4fab613f0005e8f7ef58d8df7ac671c81119189a498f84af3', 'hex'),
        2: Buffer.from('0f0b2ab4a4b0c8037e5e4a69b57a161ad61725d9238da54e4f7aef83287f48bb', 'hex'),
        3: Buffer.from('1016529e0f47127de7f27b40d479856e09d56b3b071fdfba740f70bcb13e9e8d', 'hex'),
        0xff: Buffer.from('9ec0932bd9860dc041c5dbe087cfdb207acb45207de2e9b974537a5f691fd99b', 'hex'),
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
