use crate::bolos::blake2b;
use crate::bolos::{aes::AesBOLOS, c_check_app_canary, c_device_seed};
use crate::cryptoops::{bytes_to_extended, extended_to_bytes, mul_by_cofactor, niels_multbits};
use crate::types::IvkBytes;
use crate::{
    bolos::blake2b::{
        blake2b32_with_personalization, blake2b64_with_personalization, blake2b_expand_v4,
        blake2b_expand_vec_two, blake2s_diversification,
    },
    constants::{DIV_DEFAULT_LIST_LEN, DIV_SIZE},
    cryptoops::prf_expand,
    personalization::{ZIP32_SAPLING_FVFP_PERSONALIZATION, ZIP32_SAPLING_MASTER_PERSONALIZATION},
    sapling::{sapling_ask_to_ak, sapling_nsk_to_nk},
    types::{
        diversifier_zero, AskBytes, Diversifier, DiversifierList4, DkBytes, FullViewingKey,
        FvkTagBytes, NskBytes, OvkBytes, SaplingKeyBundle, Zip32MasterChainCode, Zip32MasterKey,
        Zip32MasterSpendingKey, Zip32Path,
    },
};
use binary_ff1::BinaryFF1;
use byteorder::{ByteOrder, LittleEndian};
use jubjub::{AffinePoint, ExtendedPoint, Fr};

#[inline(never)]
// Calculates I based on https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_master_key_i() -> Zip32MasterKey {
    let seed = c_device_seed();

    Zip32MasterKey::from_bytes(&blake2b64_with_personalization(
        ZIP32_SAPLING_MASTER_PERSONALIZATION,
        &seed,
    ))
}

#[inline(never)]
// As per ask_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_ask_m(sk_m: &Zip32MasterSpendingKey) -> AskBytes {
    let t = prf_expand(sk_m, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
// As per nsk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_nsk_m(sk_m: &Zip32MasterSpendingKey) -> NskBytes {
    let t = prf_expand(sk_m, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

#[inline(never)]
// As per ovk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_ovk_m(key: &[u8; 32]) -> OvkBytes {
    let prf_output = prf_expand(key, &[0x02]);

    // truncate
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&prf_output[..32]);
    ovk
}

#[inline(never)]
// As per dk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_dk_m(sk_m: &Zip32MasterSpendingKey) -> DkBytes {
    let prf_output = prf_expand(sk_m, &[0x10]);

    // truncate
    let mut dk_m = [0u8; 32];
    dk_m.copy_from_slice(&prf_output[..32]);
    dk_m
}

#[inline(never)]
fn zip32_sapling_i_ask(sk_m: &Zip32MasterSpendingKey) -> AskBytes {
    let t = prf_expand(sk_m, &[0x13]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
fn zip32_sapling_ask_i_update(sk_m: &Zip32MasterSpendingKey, ask_i: &mut AskBytes) {
    let i_ask = zip32_sapling_i_ask(sk_m);
    *ask_i = (Fr::from_bytes(ask_i).unwrap() + Fr::from_bytes(&i_ask).unwrap()).to_bytes();
}

#[inline(never)]
fn zip32_sapling_i_nsk(sk_m: &Zip32MasterSpendingKey) -> NskBytes {
    let t = prf_expand(sk_m, &[0x14]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

#[inline(never)]
fn zip32_sapling_nsk_i_update(sk_m: &Zip32MasterSpendingKey, nsk_i: &mut NskBytes) {
    let i_nsk = zip32_sapling_i_nsk(sk_m);
    *nsk_i = (Fr::from_bytes(nsk_i).unwrap() + Fr::from_bytes(&i_nsk).unwrap()).to_bytes();
}

#[inline(never)]
fn zip32_sapling_ovk_i_update(sk_m: &[u8], ovk_i: &mut DkBytes) {
    let mut ovk_copy = [0u8; 32];
    ovk_copy.copy_from_slice(ovk_i);

    let t = &blake2b_expand_vec_two(sk_m, &[0x15], &ovk_copy);

    ovk_i.copy_from_slice(&t[0..32]);
}

#[inline(never)]
fn zip32_sapling_dk_i_update(sk_m: &[u8], dk_i: &mut DkBytes) {
    let mut dk_copy = [0u8; 32];
    dk_copy.copy_from_slice(dk_i);

    let t = &blake2b_expand_vec_two(sk_m, &[0x16], &dk_copy);

    dk_i.copy_from_slice(&t[0..32]);
}

#[inline(never)]
pub(crate) fn zip32_sapling_fvk(k: &SaplingKeyBundle) -> FullViewingKey {
    FullViewingKey::new(
        sapling_ask_to_ak(&k.ask()),
        sapling_nsk_to_nk(&k.nsk()),
        k.ovk(),
    )
}

#[inline(never)]
fn zip32_sapling_derive_child(
    ik: &mut Zip32MasterKey,
    path_i: u32,
    key_bundle_i: &mut SaplingKeyBundle,
) {
    let c = path_i & 0x7FFF_FFFF;

    let mut le_i = [0; 4];

    LittleEndian::write_u32(&mut le_i, c + (1 << 31));

    //make index LE
    //zip32 child derivation
    let c_i = &ik.chain_code();

    let prf_result = blake2b_expand_v4(c_i, &[0x11], key_bundle_i.to_bytes(), &[], &le_i);

    ik.to_bytes_mut().copy_from_slice(&prf_result);

    crate::bolos::heartbeat();

    // https://zips.z.cash/zip-0032#deriving-a-child-extended-spending-key
    zip32_sapling_ask_i_update(&ik.spending_key(), key_bundle_i.ask_mut());
    zip32_sapling_nsk_i_update(&ik.spending_key(), key_bundle_i.nsk_mut());
    zip32_sapling_ovk_i_update(&ik.spending_key(), key_bundle_i.ovk_mut());
    zip32_sapling_dk_i_update(&ik.spending_key(), key_bundle_i.dk_mut());
}

#[inline(never)]
pub fn zip32_sapling_derive(
    path: &Zip32Path,
) -> (SaplingKeyBundle, Zip32MasterChainCode, FvkTagBytes) {
    // ik as in capital I (https://zips.z.cash/zip-0032#sapling-child-key-derivation)
    let mut ik = zip32_master_key_i();

    let mut fvfp = [0u8; 4];
    let mut key_bundle_i = SaplingKeyBundle::new(
        zip32_sapling_ask_m(&ik.spending_key()),
        zip32_sapling_nsk_m(&ik.spending_key()),
        zip32_sapling_ovk_m(&ik.spending_key()),
        zip32_sapling_dk_m(&ik.spending_key()),
    );

    for path_i in path.iter().copied() {
        fvfp.copy_from_slice(
            &blake2b32_with_personalization(
                ZIP32_SAPLING_FVFP_PERSONALIZATION,
                zip32_sapling_fvk(&key_bundle_i).to_bytes(),
            )[0..4],
        );
        zip32_sapling_derive_child(&mut ik, path_i, &mut key_bundle_i);
        c_check_app_canary();
    }

    (key_bundle_i, ik.chain_code(), fvfp)
}

#[inline(never)]
pub fn diversifier_find_valid(dk: &DkBytes, start: &Diversifier) -> Diversifier {
    let mut div_list = [0u8; DIV_SIZE * DIV_DEFAULT_LIST_LEN];
    let mut div_out = diversifier_zero();

    let mut cur_div = diversifier_zero();
    cur_div.copy_from_slice(start);

    let mut found = false;
    while !found {
        // we get some small list
        diversifier_get_list(dk, &mut cur_div, &mut div_list);

        for i in 0..DIV_DEFAULT_LIST_LEN {
            let tmp = &div_list[i * DIV_SIZE..(i + 1) * DIV_SIZE]
                .try_into()
                .unwrap();

            if diversifier_is_valid(tmp) {
                div_out.copy_from_slice(tmp);
                found = true;
                break;
            }
        }

        crate::bolos::heartbeat();
    }

    div_out
}

#[inline(never)]
pub fn diversifier_get_list(
    dk: &DkBytes,
    start_diversifier: &mut Diversifier,
    result: &mut DiversifierList4,
) {
    let diversifier_list_size = 4;

    let mut scratch = [0u8; 12];

    let cipher = AesBOLOS::new(dk);
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;

    for c in 0..diversifier_list_size {
        d = *start_diversifier;
        ff1.encrypt(&mut d).unwrap();
        result[c * 11..(c + 1) * 11].copy_from_slice(&d);
        for k in 0..11 {
            start_diversifier[k] = start_diversifier[k].wrapping_add(1);
            if start_diversifier[k] != 0 {
                // No overflow
                break;
            }
        }
    }
}

#[inline(never)]
pub fn diversifier_is_valid(div_ptr: *const Diversifier) -> bool {
    let div = unsafe { &*div_ptr };
    diversifier_group_hash_light(div)
}

#[inline(never)]
pub(crate) fn diversifier_group_hash_light(tag: &[u8]) -> bool {
    if tag == diversifier_zero() {
        return false;
    }
    let hash_tag = blake2s_diversification(tag);

    //    diversifier_group_hash_check(&x)

    let u = AffinePoint::from_bytes(hash_tag);
    if u.is_some().unwrap_u8() == 1 {
        let q = u.unwrap().mul_by_cofactor();
        return q != ExtendedPoint::identity();
    }

    false
}

#[inline(never)]
pub fn pkd_default(ivk: &IvkBytes, d: &Diversifier) -> [u8; 32] {
    let h = blake2b::blake2s_diversification(d);
    let mut y = bytes_to_extended(h);

    mul_by_cofactor(&mut y);
    niels_multbits(&mut y, ivk);

    extended_to_bytes(&y)
}
