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
//! Support library for Namada Ledger Nano S/S+/X/Stax apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/ledger-namada/0.0.2")]

use ed25519_dalek::Verifier;
use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{App, AppExt, ChunkPayloadType, Version};

pub use ledger_zondax_generic::LedgerAppError;

mod params;
use params::{SignatureType, SALT_LEN, HASH_LEN, TOTAL_SIGNATURE_LEN};
pub use params::{InstructionCode, CLA, ED25519_PUBKEY_LEN, ED25519_SIGNATURE_LEN, ADDRESS_LEN};
use utils::{ResponseAddress, ResponseSignature, ResponseSignatureSection};

use std::str;

mod utils;
pub use utils::BIP44Path;

/// Ledger App Error
#[derive(Debug, thiserror::Error)]
pub enum NamError<E>
    where
        E: std::error::Error,
{
    #[error("Ledger | {0}")]
    /// Common Ledger errors
    Ledger(#[from] LedgerAppError<E>),

    // /// Device related errors
    // #[error("Secp256k1 error: {0}")]
    // Secp256k1(#[from] k256::elliptic_curve::Error),

    // /// Device related errors
    // #[error("Ecdsa error: {0}")]
    // Ecdsa(#[from] k256::ecdsa::Error),
}

/// Namada App
pub struct NamadaApp<E> {
    apdu_transport: E,
}

impl<E: Exchange> App for NamadaApp<E> {
    const CLA: u8 = CLA;
}

impl<E> NamadaApp<E> {
    /// Create a new [`NamadaApp`] with the given transport
    pub const fn new(transport: E) -> Self {
        NamadaApp {
            apdu_transport: transport,
        }
    }
}

impl<E> NamadaApp<E>
    where
        E: Exchange + Send + Sync,
        E::Error: std::error::Error,
{
    /// Retrieve the app version
    pub async fn version(&self) -> Result<Version, NamError<E::Error>> {
        <Self as AppExt<E>>::get_version(&self.apdu_transport)
            .await
            .map_err(Into::into)
    }

    /// Retrieves the public key and address
    pub async fn get_address_and_pubkey(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<ResponseAddress, NamError<E::Error>> {
        let serialized_path = path.serialize_path().unwrap();
        let p1:u8 = if require_confirmation { 1 } else { 0 };
        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetAddressAndPubkey as _,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.len() < ED25519_PUBKEY_LEN => {
                return Err(NamError::Ledger(LedgerAppError::InvalidPK))
            }
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => {
                return Err(NamError::Ledger(LedgerAppError::AppSpecific(
                    err as _,
                    err.description(),
                )))
            }
            Err(err) => {
                return Err(NamError::Ledger(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                )))
            }
        }

        let mut public_key = [0; ED25519_PUBKEY_LEN];
        public_key.copy_from_slice(&response_data[..ED25519_PUBKEY_LEN]);

        let mut address_bytes = [0; ADDRESS_LEN];
        address_bytes.copy_from_slice(&response_data[ED25519_PUBKEY_LEN..]);

        let address_str = str::from_utf8(&address_bytes).map_err(|_| LedgerAppError::Utf8)?.to_owned();

        Ok(ResponseAddress {
            public_key,
            address_bytes,
            address_str,
        })
    }

    /// Sign wrapper transaction
    pub async fn sign(
        &self,
        path: &BIP44Path,
        blob: &[u8],
    ) -> Result<ResponseSignature, NamError<E::Error>> {

        let first_chunk = path.serialize_path().unwrap();

        let start_command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::Sign as _,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: first_chunk,
        };

        let response =
            <Self as AppExt<E>>::send_chunks(&self.apdu_transport, start_command, blob).await?;

        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => {
                return Err(NamError::Ledger(LedgerAppError::AppSpecific(
                    err as _,
                    err.description(),
                )))
            }
            Err(err) => {
                return Err(NamError::Ledger(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                )))
            }
        }

        // Transactions is signed - Retrieve signatures
        let header_signature: ResponseSignatureSection = self.get_signature(SignatureType::HeaderSignature).await?;
        let data_signature: ResponseSignatureSection = self.get_signature(SignatureType::DataSignature).await?;
        let code_signature: ResponseSignatureSection = self.get_signature(SignatureType::CodeSignature).await?;

        Ok(ResponseSignature {
            header_signature,
            data_signature,
            code_signature
        })
    }

    /// Get signature section
    async fn get_signature(
        &self,
        signature_type: SignatureType,
    ) -> Result<ResponseSignatureSection, NamError<E::Error>> {

        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetSignature as _,
            p1: 0x00,
            p2: signature_type as u8,
            data: Vec::new(),
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => {
                return Err(NamError::Ledger(LedgerAppError::NoSignature))
            }
            // Last response should contain the answer
            Ok(APDUErrorCode::NoError) if response_data.len() < TOTAL_SIGNATURE_LEN => {
                return Err(NamError::Ledger(LedgerAppError::InvalidSignature))
            }
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => {
                return Err(NamError::Ledger(LedgerAppError::AppSpecific(
                    err as _,
                    err.description(),
                )))
            }
            Err(err) => {
                return Err(NamError::Ledger(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                )))
            }
        }

        let salt: [u8; SALT_LEN] = {
            let mut arr = [0u8; SALT_LEN];
            arr.copy_from_slice(&response_data[0..SALT_LEN]);
            arr
        };

        let hash: [u8; HASH_LEN] = {
            let mut arr = [0u8; HASH_LEN];
            arr.copy_from_slice(&response_data[SALT_LEN..SALT_LEN + HASH_LEN]);
            arr
        };

        let pubkey: [u8; ED25519_PUBKEY_LEN] = {
            let mut arr = [0u8; ED25519_PUBKEY_LEN];
            arr.copy_from_slice(&response_data[SALT_LEN + HASH_LEN..SALT_LEN + HASH_LEN + ED25519_PUBKEY_LEN]);
            arr
        };

        let signature: [u8; ED25519_SIGNATURE_LEN] = {
            let mut arr = [0u8; ED25519_SIGNATURE_LEN];
            arr.copy_from_slice(&response_data[SALT_LEN + HASH_LEN + ED25519_PUBKEY_LEN..SALT_LEN + HASH_LEN + ED25519_PUBKEY_LEN + ED25519_SIGNATURE_LEN]);
            arr
        };

        Ok(ResponseSignatureSection {
            salt,
            hash,
            pubkey,
            signature
        })

    }

    /// Verify signature
    pub fn verify_signature(
        &self,
        signature: &ResponseSignatureSection,
        hash: &[u8],
        pubkey: &[u8]
    ) -> bool {

        // use sha2::{Sha256, Digest};
        use ed25519_dalek::{PublicKey, Signature};

        if signature.hash != hash || signature.pubkey != pubkey {
            return false;
        }

        // Verify signature
        let public_key = PublicKey::from_bytes(&signature.pubkey).unwrap();
        let signature = Signature::from_bytes(&signature.signature).unwrap();

        public_key.verify(&hash, &signature).is_ok()
    }

}
