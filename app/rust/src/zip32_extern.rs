use crate::constants::{ZIP32_COIN_TYPE, ZIP32_PURPOSE};
use crate::sapling::{sapling_aknk_to_ivk, sapling_ask_to_ak, sapling_nsk_to_nk};
use crate::types::{
    diversifier_zero, Diversifier, DkBytes, FullViewingKey, FvkTagBytes, IvkBytes,
    Zip32MasterChainCode,
};
use crate::zip32::zip32_sapling_derive;
use crate::zip32::{self, zip32_sapling_fvk};

#[no_mangle]
pub extern "C" fn zip32_child_ask_nsk(
    account: u32,
    ask_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let ask = unsafe { &mut *ask_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    let key_bundle = zip32_sapling_derive(&path).0;

    ask.copy_from_slice(&key_bundle.ask());
    nsk.copy_from_slice(&key_bundle.nsk());
}

#[no_mangle]
pub extern "C" fn zip32_xfvk(
    account: u32,
    fvk_tag_ptr: *mut FvkTagBytes,
    cc_ptr: *mut Zip32MasterChainCode,
    fvk_ptr: *mut FullViewingKey,
    dk_ptr: *mut DkBytes,
) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let fvk_tag = unsafe { &mut *fvk_tag_ptr };
    let cc = unsafe { &mut *cc_ptr };
    let fvk_out = unsafe { &mut *fvk_ptr };
    let dk = unsafe { &mut *dk_ptr };

    let (key_bundle, chain_code, tag) = zip32_sapling_derive(&path);

    fvk_tag.copy_from_slice(&tag);
    cc.copy_from_slice(&chain_code);
    let fvk = zip32_sapling_fvk(&key_bundle);
    fvk_out.to_bytes_mut().copy_from_slice(fvk.to_bytes());
    dk.copy_from_slice(&key_bundle.dk());
}

// This only tries to find one diversifier
// Related to handleGetKeyIVK
#[no_mangle]
pub extern "C" fn diversifier_find_valid(zip32_account: u32, div_ptr: *mut Diversifier) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, zip32_account];
    let div_out = unsafe { &mut *div_ptr };

    let key_bundle = zip32_sapling_derive(&path).0;
    let dk = key_bundle.dk();

    let start = diversifier_zero();
    div_out.copy_from_slice(&zip32::diversifier_find_valid(&dk, &start));
}

#[no_mangle]
pub extern "C" fn zip32_ivk(account: u32, ivk_ptr: *mut IvkBytes) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let ivk = unsafe { &mut *ivk_ptr };

    crate::bolos::heartbeat();

    let k = zip32_sapling_derive(&path).0;
    let ak = sapling_ask_to_ak(&k.ask());
    let nk = sapling_nsk_to_nk(&k.nsk());

    let tmp_ivk = sapling_aknk_to_ivk(&ak, &nk);

    ivk.copy_from_slice(&tmp_ivk)
}

#[no_mangle]
pub extern "C" fn get_pkd(
    account: u32,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *mut [u8; 32],
) {
    let ivk_ptr = &mut [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };
    let pkd = unsafe { &mut *pkd_ptr };

    zip32_ivk(account, ivk_ptr);

    let tmp_pkd = zip32::pkd_default(ivk_ptr, diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}
