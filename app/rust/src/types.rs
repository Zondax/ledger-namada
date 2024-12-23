use ztruct::create_ztruct;

pub type AkBytes = [u8; 32];
pub type NkBytes = [u8; 32];
pub type AskBytes = [u8; 32];
pub type NskBytes = [u8; 32];
pub type OvkBytes = [u8; 32];
pub type DkBytes = [u8; 32];
pub type IvkBytes = [u8; 32];

pub type Diversifier = [u8; 11];
pub type DiversifierList4 = [u8; 44];

pub type Zip32Seed = [u8; 32];
pub type Zip32Path = [u32];
pub type Zip32MasterSpendingKey = [u8; 32];
pub type Zip32MasterChainCode = [u8; 32];

pub type FvkTagBytes = [u8; 4];

pub fn diversifier_zero() -> Diversifier {
    [0u8; 11]
}

create_ztruct! {
    //  I based on https://zips.z.cash/zip-0032#sapling-master-key-generation
    pub struct Zip32MasterKey {
        //  I_L based on https://zips.z.cash/zip-0032#sapling-master-key-generation
        pub spending_key: Zip32MasterSpendingKey,
        // I_R based on https://zips.z.cash/zip-0032#sapling-master-key-generation
        pub chain_code: Zip32MasterChainCode,
    }
}

create_ztruct! {
    pub struct SaplingKeyBundle {
        pub ask: AskBytes,
        pub nsk: NskBytes,
        pub ovk: OvkBytes,
        pub dk: DkBytes,
    }
}

create_ztruct! {
    pub struct FullViewingKey {
        pub ak: AkBytes,
        pub nk: NkBytes,
        pub ovk: OvkBytes,
    }
}
