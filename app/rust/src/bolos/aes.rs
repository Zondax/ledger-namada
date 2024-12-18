use aes::cipher::generic_array::typenum::{U16, U32, U8};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockEncrypt;
use aes::cipher::NewBlockCipher;
use aes::cipher::{BlockCipher, BlockCipherKey};
use aes::Aes256;

use super::c_zemu_log_stack;

/// Encrypts a block using AES-256.
/// This function uses the Rust `aes` crate for encryption in test environments.
pub fn aes256_encrypt_block(k: &[u8], a: &[u8]) -> Result<[u8; 16], i32> {
    let cipher = Aes256::new(GenericArray::from_slice(k));

    let mut b = GenericArray::clone_from_slice(a);
    cipher.encrypt_block(&mut b);

    // Attempt to convert to [u8; 16], return error if conversion fails
    b.as_slice().try_into().map_err(|_| -1)
}

pub struct AesBOLOS {
    key: [u8; 32],
}

impl AesBOLOS {
    pub fn new(k: &[u8; 32]) -> AesBOLOS {
        AesBOLOS { key: *k }
    }
}

impl BlockCipher for AesBOLOS {
    type BlockSize = U16;
    type ParBlocks = U8;
}

impl BlockEncrypt for AesBOLOS {
    #[inline(never)]
    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let x: [u8; 16] = block.as_slice().try_into().expect("err");
        let y = aes256_encrypt_block(&self.key, &x);
        if let Ok(y) = y {
            block.copy_from_slice(&y);
        }
    }
}
