use crate::bolos::blake2b;
use crate::bolos::blake2b::blake2b_expand_seed;
use crate::types::Diversifier;
use jubjub::{AffinePoint, ExtendedPoint, Fr};

#[inline(always)]
pub fn prf_expand(sk: &[u8], t: &[u8]) -> [u8; 64] {
    crate::bolos::heartbeat();
    blake2b_expand_seed(sk, t)
}

#[inline(never)]
pub fn mult_by_gd(scalar: &[u8; 32], d: &Diversifier) -> [u8; 32] {
    let h = blake2b::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h)
        .unwrap()
        .mul_by_cofactor()
        .to_niels();

    let t = v.multiply_bits(scalar);
    extended_to_bytes(&t)
}

#[inline(never)]
pub fn mul_by_cofactor(p: &mut ExtendedPoint) {
    *p = p.mul_by_cofactor();
}

#[inline(never)]
pub fn extended_to_u_bytes(point: &ExtendedPoint) -> [u8; 32] {
    AffinePoint::from(*point).get_u().to_bytes()
}

#[inline(never)]
pub fn extended_to_bytes(point: &ExtendedPoint) -> [u8; 32] {
    AffinePoint::from(*point).to_bytes()
}

#[inline(never)]
pub fn bytes_to_extended(m: [u8; 32]) -> ExtendedPoint {
    ExtendedPoint::from(AffinePoint::from_bytes(m).unwrap())
}

#[inline(never)]
pub fn add_to_point(point: &mut ExtendedPoint, p: &ExtendedPoint) {
    *point += p;
}

#[inline(never)]
pub fn niels_multbits(p: &mut ExtendedPoint, b: &[u8; 32]) {
    *p = p.to_niels().multiply_bits(b);
}
