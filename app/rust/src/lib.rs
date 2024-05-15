/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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
********************************************************************************/
#![no_std]
#![no_main]
#![no_builtins]
#![allow(dead_code, unused_imports)]

use core::panic::PanicInfo;

use constants::{DIV_DEFAULT_LIST_LEN, DIV_SIZE, SPENDING_KEY_GENERATOR, KEY_DIVERSIFICATION_PERSONALIZATION, GH_FIRST_BLOCK};
mod constants;
use aes::Aes256;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, NewBlockCipher,
    generic_array::{GenericArray,typenum::U32},
};
use binary_ff1::BinaryFF1;
use jubjub::{AffinePoint, ExtendedPoint, Fr};

fn debug(_msg: &str) {}

// ParserError should mirror parser_error_t from parser_common.
// At the moment, just implement OK or Error
#[repr(C)]
pub enum ParserError {
    ParserOk = 0,
    ParserUnexpectedError = 5,
}

#[repr(C)]
pub enum ConstantKey {
    SpendingKeyGenerator,
    ProofGenerationKeyGenerator,
    ValueCommitmentRandomnessGenerator,
}

#[no_mangle]
pub extern "C" fn from_bytes_wide(input: &[u8; 64], output: &mut [u8; 32]) -> ParserError {
    let result = Fr::from_bytes_wide(input).to_bytes();
    output.copy_from_slice(&result[0..32]);
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn scalar_multiplication(
    input: &[u8; 32],
    key: ConstantKey,
    output: *mut [u8; 32],
) -> ParserError {
    let key_point = match key {
        ConstantKey::SpendingKeyGenerator => constants::SPENDING_KEY_GENERATOR,
        ConstantKey::ProofGenerationKeyGenerator => constants::PROOF_GENERATION_KEY_GENERATOR,
        ConstantKey::ValueCommitmentRandomnessGenerator => constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
    };

    let extended_point = key_point.multiply_bits(input);
    let result = AffinePoint::from(&extended_point);

    unsafe {
        let output_slice = &mut *output;
        output_slice.copy_from_slice(&result.to_bytes());
    }

    ParserError::ParserOk
}

#[inline(never)]
pub fn get_diversifiers(
    dk: &[u8; 32],
    start_index: &mut [u8; 11],
    result: &mut [u8; 44],
) {
    // Initialize cipher
    let key = GenericArray::from_slice(dk);
    let cipher = Aes256::new(&key);
    let mut scratch = [0; 12];

    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: [u8; 11];
    let size = 4;

    for c in 0..size {
        d = *start_index;
        ff1.encrypt(&mut d).unwrap();
        result[c * 11..(c + 1) * 11].copy_from_slice(&d);
        for k in 0..11 {
            start_index[k] = start_index[k].wrapping_add(1);
            if start_index[k] != 0 {
                // No overflow
                break;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn get_default_diversifier_list(
    dk: &[u8; 32],
    start_index: &mut [u8; 11],
    d_l: &mut [u8; 44],
) -> ParserError {
    let start = &mut *start_index;
    let diversifier =  &mut *d_l;
    get_diversifiers(dk,  start, diversifier);
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn is_valid_diversifier(
    hash: &[u8; 32],
) -> bool {
    let u = AffinePoint::from_bytes(*hash);
    if u.is_some().unwrap_u8() == 1 {
        let q = u.unwrap().mul_by_cofactor();
        return q != ExtendedPoint::identity();
    }

    false
}

#[no_mangle]
pub extern "C" fn get_pkd(
    ivk_ptr: &[u8; 32],
    h: &[u8; 32],
    pk_d: &mut [u8; 32],
) -> ParserError {

    let affine = AffinePoint::from_bytes(*h).unwrap();
    let extended = ExtendedPoint::from(affine);
    let cofactor = extended.mul_by_cofactor();
    let p = cofactor.to_niels().multiply_bits(ivk_ptr);
    *pk_d = AffinePoint::from(p).to_bytes();

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn randomized_secret_from_seed(
    ask:  &[u8; 32],
    alpha:  &[u8; 32],
    output:  &mut [u8; 32],
) -> ParserError{

    let mut skfr = Fr::from_bytes(ask).unwrap();
    let alphafr = Fr::from_bytes(alpha).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn compute_sbar(
    s:  &[u8; 32],
    r:  &[u8; 32],
    rsk:  &[u8; 32],
    sbar:  &mut [u8; 32],
) -> ParserError{
    let s_point = Fr::from_bytes(s).unwrap();
    let r_point = Fr::from_bytes(r).unwrap();
    let rsk_point = Fr::from_bytes(rsk).unwrap();

    let sbar_tmp = r_point + s_point * rsk_point;
    sbar.copy_from_slice(&sbar_tmp.to_bytes());
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn add_points(
    hash:  &[u8; 32],
    value: &[u8; 32],
    scalar:  &[u8; 32],
    cv:  &mut [u8; 32]) -> ParserError{

    let hash_point = AffinePoint::from_bytes(*hash).unwrap();
    let hash_point_ex = ExtendedPoint::from(hash_point);
    let cofactor = hash_point_ex.mul_by_cofactor();

    let val = Fr::from_bytes(value).unwrap();
    
    let scale = AffinePoint::from_bytes(*scalar).unwrap();
    let scale_extended = ExtendedPoint::from(scale);

    let s = cofactor*val + scale_extended;
    let vcm = AffinePoint::from(s).to_bytes();
    cv.copy_from_slice(&vcm);
    ParserError::ParserOk
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    // use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    // use curve25519_dalek::edwards::EdwardsPoint;
    // use curve25519_dalek::scalar::Scalar;
    // use log::{debug, info};
    // use schnorrkel::{context::*, Keypair, PublicKey, SecretKey, Signature};

    // use crate::*;
    // use core::ops::Mul;

    // fn init_logging() {
    //     let _ = env_logger::builder().is_test(true).try_init();
    // }

    // fn ristretto_scalarmult(sk: &[u8], pk: &mut [u8]) {
    //     let mut seckey = [0u8; 32];
    //     seckey.copy_from_slice(&sk[0..32]);
    //     let pubkey = RISTRETTO_BASEPOINT_POINT
    //         .mul(Scalar::from_bits(seckey))
    //         .compress()
    //         .0;
    //     pk.copy_from_slice(&pubkey);
    // }

}
