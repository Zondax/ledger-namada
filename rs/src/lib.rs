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
//! Support library for Namada Ledger Nano S/S+/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/ledger-namada/0.0.2")]

use leb128;
use ed25519_dalek::Verifier;
use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{App, AppExt, ChunkPayloadType, Version};

use byteorder::{LittleEndian, WriteBytesExt};

pub use ledger_zondax_generic::LedgerAppError;

mod params;
pub use params::{InstructionCode, CLA, ED25519_PUBKEY_LEN, ED25519_SIGNATURE_LEN, ADDRESS_LEN};
use utils::{ResponseAddress, ResponseSignatureWrapperTransaction};

use std::str;

mod utils;
pub use utils::BIP44Path;

use prost_types::Timestamp;

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
    pub async fn sign_wrapper_transaction(
        &self,
        path: &BIP44Path,
        code: &[u8],
        data: &[u8],
        timestamp: &Timestamp,
    ) -> Result<ResponseSignatureWrapperTransaction, NamError<E::Error>> {

        let first_chunk = path.serialize_path().unwrap();

        let start_command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::SignWrapperTransaction as _,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: first_chunk,
        };

        let mut message = Vec::new();
        message.write_u32::<LittleEndian>(code.len() as u32).unwrap();
        message.write_u32::<LittleEndian>(data.len() as u32).unwrap();
        message.extend(code);
        message.extend(data);
        message.write_i64::<LittleEndian>(timestamp.seconds).unwrap();
        message.write_i32::<LittleEndian>(timestamp.nanos).unwrap();


        let response =
            <Self as AppExt<E>>::send_chunks(&self.apdu_transport, start_command, &message).await?;

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => {
                return Err(NamError::Ledger(LedgerAppError::NoSignature))
            }
            // Last response should contain the answer
            Ok(APDUErrorCode::NoError) if response_data.len() < ED25519_SIGNATURE_LEN => {
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

        let mut signature = [0; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&response_data[..ED25519_SIGNATURE_LEN]);

        Ok(ResponseSignatureWrapperTransaction {
            signature
        })
    }

    fn serialize_timestamp(
        &self,
        timestamp: &Timestamp
    ) -> Result<Vec<u8>, NamError<E::Error>> {

        let mut buffer = Vec::new();
        let mut leb_seconds = Vec::new();
        let mut leb_nanos = Vec::new();

        leb128::write::signed(&mut leb_seconds, timestamp.seconds).expect("Invalid seconds param");
        leb128::write::signed(&mut leb_nanos, timestamp.nanos as i64).expect("Invalid nanos param");

        if timestamp.seconds > 0 {
            buffer.extend(&[0x08]);
            buffer.append(&mut leb_seconds);
        }
        if timestamp.nanos > 0 {
            buffer.extend(&[0x10]);
            buffer.append(&mut leb_nanos);
        }

        let mut timestamp_size = Vec::new();
        leb128::write::unsigned(&mut timestamp_size, buffer.len() as u64).expect("Invalid timestamp size");
        buffer.insert(0, timestamp_size[0]);
        buffer.insert(0, 0x1A);

        Ok(buffer)
    }

    /// Verify signature from a wrapper transaction
    pub fn verify_wrapper_transaction_signature(
        &self,
        code: &[u8],
        data: &[u8],
        timestamp: &Timestamp,
        pubkey: &[u8],
        signature: &[u8]
    ) -> bool {

        use sha2::{Sha256, Digest};
        use ed25519_dalek::{PublicKey, Signature};

        let mut serialized_outer_transaction = Vec::new();
        let mut serialized_code = Vec::new();
        let mut serialized_data = Vec::new();


        let code_hash = Sha256::digest(&code);
        leb128::write::signed(&mut serialized_code, code_hash.len() as i64).expect("Invalid LEB128 encoding");
        serialized_code.extend(code_hash);

        leb128::write::signed(&mut serialized_data, data.len() as i64).expect("Invalid LEB128 encoding");
        serialized_data.extend(data);

        // Code
        serialized_outer_transaction.extend(&[0x0A]);
        serialized_outer_transaction.append(&mut serialized_code);

        // Data
        serialized_outer_transaction.extend(&[0x12]);
        serialized_outer_transaction.append(&mut serialized_data);

        // Timestamp
        let mut serialized_timestamp = self.serialize_timestamp(timestamp).unwrap();
        serialized_outer_transaction.append(&mut serialized_timestamp);

        let bytes_to_sign = Sha256::digest(&serialized_outer_transaction);

        // Verify signature
        let public_key = PublicKey::from_bytes(&pubkey).unwrap();
        let signature = Signature::from_bytes(&signature).unwrap();

        public_key.verify(&bytes_to_sign, &signature).is_ok()
    }

}
