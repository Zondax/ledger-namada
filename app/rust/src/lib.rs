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

#[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing"),))]
use core::panic::PanicInfo;

use constants::{DIV_DEFAULT_LIST_LEN, DIV_SIZE, GH_FIRST_BLOCK, SPENDING_KEY_GENERATOR};
mod bolos;
mod constants;
mod cryptoops;
mod personalization;
mod sapling;
mod types;
mod zip32;
mod zip32_extern;
use aes::cipher::{
    generic_array::{typenum::U32, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};
use aes::Aes256;
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
        ConstantKey::ProofGenerationKeyGenerator => constants::PROVING_KEY_BASE,
        ConstantKey::ValueCommitmentRandomnessGenerator => {
            constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR
        }
    };

    let extended_point = key_point.multiply_bits(input);
    let result = AffinePoint::from(&extended_point);

    unsafe {
        let output_slice = &mut *output;
        output_slice.copy_from_slice(&result.to_bytes());
    }

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn is_valid_diversifier(hash: &[u8; 32]) -> ParserError {
    let u = AffinePoint::from_bytes(*hash);

    // Check if the CtOption is Some
    if u.is_some().into() {
        // Convert CtOption to bool
        let point = u.unwrap(); // Safe to unwrap since we checked is_some
        let q = point.mul_by_cofactor(); // Use the point directly
        if q != ExtendedPoint::identity() {
            return ParserError::ParserOk; // Valid diversifier
        }
    }

    ParserError::ParserUnexpectedError // Return error if the point is not valid
}

#[no_mangle]
pub extern "C" fn randomized_secret_from_seed(
    ask: &[u8; 32],
    alpha: &[u8; 32],
    output: &mut [u8; 32],
) -> ParserError {
    let skfr = Fr::from_bytes(ask);
    if skfr.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for ask
    }
    let skfr = skfr.unwrap(); // Safe to unwrap since we checked is_none

    let alphafr = Fr::from_bytes(alpha);
    if alphafr.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for alpha
    }
    let alphafr = alphafr.unwrap(); // Safe to unwrap since we checked is_none

    let skfr_result = skfr + alphafr;
    output.copy_from_slice(&skfr_result.to_bytes());

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn compute_sbar(
    s: &[u8; 32],
    r: &[u8; 32],
    rsk: &[u8; 32],
    sbar: &mut [u8; 32],
) -> ParserError {
    let s_point = Fr::from_bytes(s);
    if s_point.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for s
    }
    let s_point = s_point.unwrap(); // Safe to unwrap since we checked is_none

    let r_point = Fr::from_bytes(r);
    if r_point.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for r
    }
    let r_point = r_point.unwrap(); // Safe to unwrap since we checked is_none

    let rsk_point = Fr::from_bytes(rsk);
    if rsk_point.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for rsk
    }
    let rsk_point = rsk_point.unwrap(); // Safe to unwrap since we checked is_none

    let sbar_tmp = r_point + s_point * rsk_point;
    sbar.copy_from_slice(&sbar_tmp.to_bytes());
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn add_points(
    hash: &[u8; 32],
    value: &[u8; 32],
    scalar: &[u8; 32],
    cv: &mut [u8; 32],
) -> ParserError {
    let hash_point = AffinePoint::from_bytes(*hash);
    if hash_point.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for hash
    }
    let hash_point = hash_point.unwrap(); // Safe to unwrap since we checked is_none
    let hash_point_ex = ExtendedPoint::from(hash_point);
    let cofactor = hash_point_ex.mul_by_cofactor();

    let val = Fr::from_bytes(value).unwrap();

    let scale = AffinePoint::from_bytes(*scalar);
    if scale.is_none().into() {
        return ParserError::ParserUnexpectedError; // Handle error for scalar
    }
    let scale = scale.unwrap(); // Safe to unwrap since we checked is_none
    let scale_extended = ExtendedPoint::from(scale);

    let s = cofactor * val + scale_extended;
    let vcm = AffinePoint::from(s).to_bytes();
    cv.copy_from_slice(&vcm);
    ParserError::ParserOk
}

#[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing"),))]
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
