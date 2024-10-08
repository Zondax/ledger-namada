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

use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub use ledger_zondax_generic::LedgerAppError;

mod params;
pub use params::{
    InstructionCode, KeyResponse, NamadaKeys, ADDRESS_LEN, CLA, ED25519_PUBKEY_LEN,
    PK_LEN_PLUS_TAG, SIG_LEN_PLUS_TAG,
};
use params::{KEY_LEN, SALT_LEN};
use utils::{
    ResponseAddress, ResponseGetConvertRandomness, ResponseGetOutputRandomness,
    ResponseGetSpendRandomness, ResponseMaspSign, ResponseProofGenKey, ResponsePubAddress,
    ResponseSignature, ResponseSpendSignature, ResponseViewKey,
};

use std::convert::TryInto;
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
        let p1: u8 = if require_confirmation { 1 } else { 0 };
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

        let (raw_public_key, rest) = response_data.split_at(ED25519_PUBKEY_LEN + 1);
        let (public_key_len, rest) = rest.split_first().expect("response too short");
        let (_public_key, rest) = rest.split_at((*public_key_len).into());
        let (address_len, rest) = rest.split_first().expect("response too short");
        let (address_bytes, rest) = rest.split_at((*address_len).into());
        if rest.len() > 0 {
            panic!("response too long");
        }

        let address_str = str::from_utf8(&address_bytes)
            .map_err(|_| LedgerAppError::Utf8)?
            .to_owned();

        Ok(ResponseAddress {
            public_key: raw_public_key.try_into().unwrap(),
            address_bytes: address_bytes.try_into().unwrap(),
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
        let rest = response.apdu_data();
        let (pubkey, rest) = rest.split_at(PK_LEN_PLUS_TAG);
        let (raw_salt, rest) = rest.split_at(SALT_LEN);
        let (raw_signature, rest) = rest.split_at(SIG_LEN_PLUS_TAG);
        let (wrapper_salt, rest) = rest.split_at(SALT_LEN);
        let (wrapper_signature, rest) = rest.split_at(SIG_LEN_PLUS_TAG);
        let (raw_indices_len, rest) = rest.split_at(1);
        let (raw_indices, rest) = rest.split_at(raw_indices_len[0] as usize);
        let (wrapper_indices_len, rest) = rest.split_at(1);
        let (wrapper_indices, _rest) = rest.split_at(wrapper_indices_len[0] as usize);

        Ok(ResponseSignature {
            pubkey: pubkey.try_into().unwrap(),
            raw_salt: raw_salt.try_into().unwrap(),
            raw_signature: raw_signature.try_into().unwrap(),
            wrapper_salt: wrapper_salt.try_into().unwrap(),
            wrapper_signature: wrapper_signature.try_into().unwrap(),
            raw_indices: raw_indices.into(),
            wrapper_indices: wrapper_indices.into(),
        })
    }

    /// Compute hash from signature section
    pub fn hash_signature_sec(
        &self,
        pubkeys: Vec<Vec<u8>>,
        hashes: &HashMap<usize, Vec<u8>>,
        indices: Vec<u8>,
        signature: Option<Vec<u8>>,
        prefix: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();

        if let Some(prefix) = prefix {
            hasher.update(prefix);
        }

        hasher.update((indices.len() as u32).to_le_bytes());
        for &index in &indices {
            hasher.update(&hashes[&(index as usize)]);
        }

        hasher.update([0x01]);

        hasher.update(&[pubkeys.len() as u8, 0, 0, 0]);
        for pubkey in pubkeys {
            hasher.update(pubkey);
        }

        match signature {
            Some(sig) => {
                hasher.update([1, 0, 0, 0]);
                hasher.update([0x00]);
                hasher.update(sig);
            }
            None => {
                hasher.update([0, 0, 0, 0]);
            }
        }

        hasher.finalize().to_vec()
    }

    /// Verify signature
    pub fn verify_signature(
        &self,
        signature: &ResponseSignature,
        section_hashes: HashMap<usize, Vec<u8>>,
        pubkey: &[u8],
    ) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};

        if pubkey != &signature.pubkey {
            return false;
        }

        let mut public_key_bytes = [0u8; 32];
        public_key_bytes.copy_from_slice(&signature.pubkey[1..33]);
        let public_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        let unsigned_raw_sig_hash = self.hash_signature_sec(
            vec![],
            &section_hashes,
            signature.raw_indices.clone(),
            None,
            None,
        );
        let mut raw_signature_bytes = [0u8; 64];
        raw_signature_bytes.copy_from_slice(&signature.raw_signature[1..65]);
        let raw_signature = Signature::from_bytes(&raw_signature_bytes);
        let raw_sig = public_key
            .verify(&unsigned_raw_sig_hash, &raw_signature)
            .is_ok();

        // Verify wrapper signature
        let prefix: Vec<u8> = vec![0x03];
        let raw_hash = self.hash_signature_sec(
            vec![signature.pubkey.to_vec()],
            &section_hashes,
            signature.raw_indices.clone(),
            Some(signature.raw_signature.to_vec()),
            Some(prefix),
        );

        let mut tmp_hashes = section_hashes.clone();
        tmp_hashes.insert(tmp_hashes.len() - 1, raw_hash);

        let unsigned_wrapper_sig_hash = self.hash_signature_sec(
            vec![],
            &tmp_hashes,
            signature.wrapper_indices.clone(),
            None,
            None,
        );

        let mut wrapper_signature_bytes = [0u8; 64];
        wrapper_signature_bytes.copy_from_slice(&signature.wrapper_signature[1..65]);
        let wrapper_signature = Signature::from_bytes(&wrapper_signature_bytes);
        let wrapper_sig = public_key
            .verify(&unsigned_wrapper_sig_hash, &wrapper_signature)
            .is_ok();

        raw_sig && wrapper_sig
    }

    /// Retrieve masp keys from the Namada app
    pub async fn retrieve_keys(
        &self,
        path: &BIP44Path,
        key_type: NamadaKeys,
        require_confirmation: bool,
    ) -> Result<KeyResponse, NamError<E::Error>> {
        let serialized_path = path.serialize_path().unwrap();
        let p1: u8 = if require_confirmation { 1 } else { 0 };

        let p2: u8 = match key_type {
            NamadaKeys::PublicAddress => 0,
            NamadaKeys::ViewKey => 1,
            NamadaKeys::ProofGenerationKey => 2,
        };

        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetKeys as _,
            p1,
            p2,
            data: serialized_path,
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

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

        let response_data = response.apdu_data();
        match key_type {
            NamadaKeys::PublicAddress => Ok(KeyResponse::Address(ResponsePubAddress {
                public_address: response_data[..KEY_LEN].try_into().unwrap(),
            })),
            NamadaKeys::ViewKey => {
                let (view_key, rest) = response_data.split_at(2 * KEY_LEN);
                let (ovk, rest) = rest.split_at(KEY_LEN);
                let (ivk, _) = rest.split_at(KEY_LEN);
                let (dk, _) = rest.split_at(KEY_LEN);
                Ok(KeyResponse::ViewKey(ResponseViewKey {
                    view_key: view_key.try_into().unwrap(),
                    ovk: ovk.try_into().unwrap(),
                    ivk: ivk.try_into().unwrap(),
                    dk: dk.try_into().unwrap(),
                }))
            }
            NamadaKeys::ProofGenerationKey => {
                let (ak, rest) = response_data.split_at(KEY_LEN);
                let (nsk, _) = rest.split_at(KEY_LEN);
                Ok(KeyResponse::ProofGenKey(ResponseProofGenKey {
                    ak: ak.try_into().unwrap(),
                    nsk: nsk.try_into().unwrap(),
                }))
            }
        }
    }

    /// Get Randomness for Spend
    pub async fn get_spend_randomness(
        &self,
    ) -> Result<ResponseGetSpendRandomness, NamError<E::Error>> {
        let arr: &[u8] = &[];
        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetSpendRandomness as _,
            p1: 0x00,
            p2: 0x00,
            data: arr, // Send empty data
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

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

        let response_data = response.apdu_data();
        if response_data.len() < 2 * KEY_LEN {
            return Err(NamError::Ledger(LedgerAppError::InvalidMessageSize));
        }

        let (rcv, rest) = response_data.split_at(KEY_LEN);
        let (alpha, _) = rest.split_at(KEY_LEN);
        Ok(ResponseGetSpendRandomness {
            rcv: rcv.try_into().unwrap(),
            alpha: alpha.try_into().unwrap(),
        })
    }

    /// Get Randomness for convert
    pub async fn get_convert_randomness(
        &self,
    ) -> Result<ResponseGetConvertRandomness, NamError<E::Error>> {
        let arr: &[u8] = &[];
        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetConvertRandomness as _,
            p1: 0x00,
            p2: 0x00,
            data: arr, // Send empty data
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

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

        let response_data = response.apdu_data();
        if response_data.len() < KEY_LEN {
            return Err(NamError::Ledger(LedgerAppError::InvalidMessageSize));
        }

        let (rcv, _) = response_data.split_at(KEY_LEN);
        Ok(ResponseGetConvertRandomness {
            rcv: rcv.try_into().unwrap(),
        })
    }

    /// Get Randomness for output
    pub async fn get_output_randomness(
        &self,
    ) -> Result<ResponseGetOutputRandomness, NamError<E::Error>> {
        let arr: &[u8] = &[];
        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetOutputRandomness as _,
            p1: 0x00,
            p2: 0x00,
            data: arr, // Send empty data
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

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

        let response_data = response.apdu_data();
        if response_data.len() < 2 * KEY_LEN {
            return Err(NamError::Ledger(LedgerAppError::InvalidMessageSize));
        }

        let (rcv, rest) = response_data.split_at(KEY_LEN);
        let (rcm, _) = rest.split_at(KEY_LEN);
        Ok(ResponseGetOutputRandomness {
            rcv: rcv.try_into().unwrap(),
            rcm: rcm.try_into().unwrap(),
        })
    }

    /// Get Spend signature
    pub async fn get_spend_signature(&self) -> Result<ResponseSpendSignature, NamError<E::Error>> {
        let arr: &[u8] = &[];
        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::ExtractSpendSignature as _,
            p1: 0x00,
            p2: 0x00,
            data: arr, // Send empty data
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

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

        let response_data = response.apdu_data();
        if response_data.len() < 2 * KEY_LEN {
            return Err(NamError::Ledger(LedgerAppError::InvalidMessageSize));
        }

        let (rbar, rest) = response_data.split_at(KEY_LEN);
        let (sbar, _) = rest.split_at(KEY_LEN);
        Ok(ResponseSpendSignature {
            rbar: rbar.try_into().unwrap(),
            sbar: sbar.try_into().unwrap(),
        })
    }

    /// Sign Masp signing
    pub async fn sign_masp_spends(
        &self,
        path: &BIP44Path,
        blob: &[u8],
    ) -> Result<ResponseMaspSign, NamError<E::Error>> {
        let first_chunk = path.serialize_path().unwrap();

        let start_command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::SignMaspSpends as _,
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
        let rest = response.apdu_data();
        let (hash, _) = rest.split_at(KEY_LEN);

        Ok(ResponseMaspSign {
            hash: hash.try_into().unwrap(),
        })
    }

    /// Clean buffers
    pub async fn clean_randomness_buffers(&self) -> Result<(), NamError<E::Error>> {
        let arr: &[u8] = &[];
        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::CleanBuffers as _,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: arr, // Send empty data
        };

        self.apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;
        Ok(())
    }
}
