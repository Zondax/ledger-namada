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

/// App identifier
pub const CLA: u8 = 0x57;

/// Public Key Length
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Address array size
pub const ADDRESS_LEN: usize = 84;  // 84 --> Testnet | 80 --> Mainnet
/// ED25519 signature Length
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Available instructions to interact with the Ledger device
#[repr(u8)]
pub enum InstructionCode {
    /// Instruction to retrieve Pubkey and Address
    GetAddressAndPubkey = 1,
    /// Instruction to sign a wrapper transaction
    SignWrapperTransaction = 2,
}
