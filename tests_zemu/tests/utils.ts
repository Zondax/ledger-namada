const sha256 = require('js-sha256')

export function hashSignatureSec(pubkeys: Buffer[], salt: Buffer, hashes: { [index: number]: Buffer }, indices: Buffer, signature: Buffer | null, prefix: Uint8Array | null) {
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
