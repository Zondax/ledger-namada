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
    blob: Buffer.from('080000003544385f3164664101250000002b39323138352d30362d32325432323a31333a31362e3431363932343933352b30303a3030260000002b3137343538352d30392d32365430383a32393a34362e3137373934303830382b30303a3030cfd682b57a59570469dacf8bc0ecaf4d9c8e99042c5f8021866490963af04d32f14b247ff77993f5a8ca352a6c163003838a69b435d95249172e419ef192e8660000000000000000000000000000000000000000000000000000000000000000018b8b2b36a1f47fa00000000000000000000000000000000000000000000000009d00b8ba65871cf8dbd943b629650d7a059f15addb6d01036a9efcd99d25af6eba15f6c045341c2d41ecd099df64f10504e676849a1f121be22aa5bb4c8375bf5412d9e87ef2843f00040000000109d0afb45dd8e60a00ac4ce1202f723171b9b6937edf7b06f794637a9fec932a1f4b42bdc85b7a2c2100008718488d8d0100000301000001e2dbb142695229f10e7b48dd473b9578b803ac7701d9e9984574d4d1b7f291ea6e2be64f8e1ab9e9b92ced91ddb08eef069970bcbb0600000000b4f03a6faad2247340c93fd981a40f14980f4bd4b314f66209afaa6fc1f5cdda006be58a8ca12b287e9c9bd8d216021182d8af31d4c3181783ab52381d62880f7001020f240cfac2269291212c8fdbd78b42be512c7cfbddab33c1d1132d864356fbf600e50b48db57477fddf8ed278177f94721306d33ff413f207393ef6b73b924a97f00552130d1b02487b8afaf10e81afeba1d34cc3824900374c66249521fa264bfcd009d4715a2097bfb00abc5616f9c401e15cc58cf347f9b5cb5b59aa13dd2deb2920101028718488d8d01000000695f90b686a8b49d9ae9192297816f8235ca56a19e8986f4bf157a3544d36523011600000074785f7570646174655f6163636f756e742e7761736d0304000000d4f87aba4c1d42fd4d3a20b720902f1716a1379d4f5c1924bcfa56828fda6cd2d9e9984574d4d1b7f291ea6e2be64f8e1ab9e9b92ced91ddb08eef069970bcbbf14b247ff77993f5a8ca352a6c163003838a69b435d95249172e419ef192e866cfd682b57a59570469dacf8bc0ecaf4d9c8e99042c5f8021866490963af04d320101000000007c5c4053721b82189e53b2712127f816055ff4fa61b664d2eff2185314ecccc1010000000000adf360c824bb8f4102aaf2116393154175c0bc3892e2337013c3fe41a20f7123138f575e3c89793d75a12bcb7b09628839dd8658580860cd76e5cd461c571708', 'hex'),
    sectionHashes: {
      0: Buffer.from('d4f87aba4c1d42fd4d3a20b720902f1716a1379d4f5c1924bcfa56828fda6cd2', 'hex'),
      1: Buffer.from('d9e9984574d4d1b7f291ea6e2be64f8e1ab9e9b92ced91ddb08eef069970bcbb', 'hex'),
      2: Buffer.from('f14b247ff77993f5a8ca352a6c163003838a69b435d95249172e419ef192e866', 'hex'),
      3: Buffer.from('cfd682b57a59570469dacf8bc0ecaf4d9c8e99042c5f8021866490963af04d32', 'hex'),
      4: Buffer.from('8111d43c3c89850da89b6ec3ba8c9fe74cf8150c6373acd0e4063882d7f1901f', 'hex'),
      0xff: Buffer.from('3510e24f580d5b12d38ab204e0ac981294965ba6764422cb7c8aba57d39b6f0d', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_address',
    blob: Buffer.from('1f000000723563395536555f5f304d327a4139444156367630347a5f395f6e5078565300260000002d3232373133342d31322d32345430363a33323a30302e3735313931373138342b30303a30308ec463fe38e9718fa6e8b5b2f98709eaa6db8076481101c3fa4a56d054bbc0f07dccc867ec89cc4a0cb7ab52a1f1cb1012dda5e16d0ef33987a0b6fede34867def2a5c196d87a4093ec1b66a19544eb963e25e44d333c63a1bea6e4e55bbb5f40190b56a3f5857ea4d000000000000000000000000000000000000000000000000cd00cfe500ea0fdff3c28cfc002ab505b580dff32e3101033dc29d939d6e10e51664bf504e72fd30c178a5b44963cebe5b6427593aff8bfcba8307484595650d71160aefb81cbc6b0189cfcbf0e70cf05e8f200248222192c1e7fa966726eb42910a484af0d15810bb0500000000a218488d8d0100001600000000fee0b49fc31bb149da684b00d16a1f64c1030b690002a218488d8d01000000466543907b8b5f5647223438eec0468bf0754f1b9fbe0c335a86a1c0efbf779e011000000074785f77697468647261772e7761736d0185f18bc6413ce7820101000000350101000000410304000000615c7d773cef3bd19673d2e796bee44b06b120be6c91c40afa1a24f9f9d78b197dccc867ec89cc4a0cb7ab52a1f1cb1012dda5e16d0ef33987a0b6fede34867d8ec463fe38e9718fa6e8b5b2f98709eaa6db8076481101c3fa4a56d054bbc0f0ef2a5c196d87a4093ec1b66a19544eb963e25e44d333c63a1bea6e4e55bbb5f4010200000000b85245a22922ffaf61c32f9dc933facdf7ae0e32715dd82aa3c52f92d5213caa009404673e3c00c0dd26991f0be75f9725c069b1b51f13a6c9fa876ef3ec7647ec020000000000c97ab66be78ca5d55da81971b114cde3a7cfdba8afb9889e0b9aa77d6604d8222c38c5056c1d547c6950cc988c4479615fe97986994b1d0bc03f3a26b4712c010100cd634e538a674e31c35a08156443079b4e8d2ec2921951354459a57bdab645d1f64a3e9eca0b6b8b80f4e4bfd3e8f7925fc21fcd7895177ffbe99de1cd4ff10f0304000000615c7d773cef3bd19673d2e796bee44b06b120be6c91c40afa1a24f9f9d78b197dccc867ec89cc4a0cb7ab52a1f1cb1012dda5e16d0ef33987a0b6fede34867d8ec463fe38e9718fa6e8b5b2f98709eaa6db8076481101c3fa4a56d054bbc0f0ef2a5c196d87a4093ec1b66a19544eb963e25e44d333c63a1bea6e4e55bbb5f400009d5ef189336901c01667559baab8327d3d73ecf301000000da00a403c51956647a6f6b81813692e19b4448536ec9061a55feb8fe6588113fdd06c2175878b4bfa72ef8b1114a731b6ad37da329277c53fb0c3376154e2bb18102', 'hex'),
    sectionHashes: {
      0: Buffer.from('615c7d773cef3bd19673d2e796bee44b06b120be6c91c40afa1a24f9f9d78b19', 'hex'),
      1: Buffer.from('7dccc867ec89cc4a0cb7ab52a1f1cb1012dda5e16d0ef33987a0b6fede34867d', 'hex'),
      2: Buffer.from('8ec463fe38e9718fa6e8b5b2f98709eaa6db8076481101c3fa4a56d054bbc0f0', 'hex'),
      3: Buffer.from('ef2a5c196d87a4093ec1b66a19544eb963e25e44d333c63a1bea6e4e55bbb5f4', 'hex'),
      4: Buffer.from('026f73ef4ad3a77ac9288605d96a45dfd315b5491f55764116d8e7474b7eb7db', 'hex'),
      5: Buffer.from('7d814004268deaf62d60d24d22cb6d86d95fd7fdd1160747e49378dc09da08e2', 'hex'),
      0xff: Buffer.from('1b03941b2da6fc081f5233f8b640516f83dc329abc8090f323b63ef4d42f8c2b', 'hex'),
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
