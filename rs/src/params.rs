/*******************************************************************************
*   (c) 2018 - 2023 ZondaX AG
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
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

use crate::utils::{ResponseProofGenKey, ResponsePubAddress, ResponseViewKey};

/// App identifier
pub const CLA: u8 = 0x57;

/// MASP keys len
pub const KEY_LEN: usize = 32;
/// Public Key Length
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Public Key + Tag Length
pub const PK_LEN_PLUS_TAG: usize = ED25519_PUBKEY_LEN + 1;
/// Address array size
pub const ADDRESS_LEN: usize = 45; // 45 --> Testnet | 42 --> Mainnet
/// ED25519 signature Length
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ED25519 signature + Tag Length
pub const SIG_LEN_PLUS_TAG: usize = ED25519_SIGNATURE_LEN + 1;
/// Salt Length
pub const SALT_LEN: usize = 8;
/// Hash Length
// pub const HASH_LEN: usize = 32;
/// Available instructions to interact with the Ledger device
#[repr(u8)]
pub enum InstructionCode {
    /// Instruction to retrieve Pubkey and Address
    GetAddressAndPubkey = 1,
    /// Instruction to sign a transaction
    Sign = 2,
    /// Instruction to retrieve MASP keys
    GetKeys = 3,
    /// Instruction to generate spend randomness values
    GetSpendRandomness = 4,
    /// Instruction to generate output randomness values
    GetOutputRandomness = 5,
    /// Instruction to generate spend convert values
    GetConvertRandomness = 6,
    /// Instruction to sign masp
    SignMaspSpends = 7,
    /// Instruction to retrieve spend signatures
    ExtractSpendSignature = 8,
    /// Instruction to clean Buffers
    CleanBuffers = 0x09,

    /// Instruction to retrieve a signed section
    GetSignature = 0x0a,
}

#[derive(Clone, Debug)]
/// Masp keys return types
pub enum NamadaKeys {
    /// Public address key
    PublicAddress = 0x00,
    /// View key
    ViewKey = 0x01,
    /// Proof generation key
    ProofGenerationKey = 0x02,
}

/// Types of Keys Response
pub enum KeyResponse {
    /// Address response
    Address(ResponsePubAddress),
    /// View key response
    ViewKey(ResponseViewKey),
    /// Proof generation key response
    ProofGenKey(ResponseProofGenKey),
}
