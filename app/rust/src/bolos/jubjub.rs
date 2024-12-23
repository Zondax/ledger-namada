use crate::bolos::canary::c_check_app_canary;
use crate::{bolos, constants};
use jubjub::AffinePoint;

pub fn scalarmult(point: &mut [u8], scalar: &[u8]) {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(point);
    let mut scalarbytes = [0u8; 32];
    scalarbytes.copy_from_slice(scalar);
    let result = AffinePoint::from_bytes(bytes)
        .unwrap()
        .to_niels()
        .multiply_bits(&scalarbytes);
    point.copy_from_slice(&AffinePoint::from(result).to_bytes());
}

pub fn scalarmult_spending_base(point: &mut [u8], scalar: &[u8]) {
    let mut scalarbytes = [0u8; 32];
    scalarbytes.copy_from_slice(scalar);
    let result = constants::SPENDING_KEY_GENERATOR.multiply_bits(&scalarbytes);
    point.copy_from_slice(&AffinePoint::from(result).to_bytes());
}
