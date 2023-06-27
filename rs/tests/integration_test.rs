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
// Integration tests

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

extern crate ledger_namada_rs;

use ledger_namada_rs::{BIP44Path, NamadaApp, ED25519_PUBKEY_LEN};
use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
use hex::FromHex;
use once_cell::sync::Lazy;
use serial_test::serial;

static HIDAPI: Lazy<HidApi> = Lazy::new(|| HidApi::new().expect("Failed to create Hidapi"));

fn app() -> NamadaApp<TransportNativeHID> {
    NamadaApp::new(TransportNativeHID::new(&HIDAPI).expect("unable to create transport"))
}


#[tokio::test]
#[serial]
async fn version() {
    let app = app();

    let version = app.version().await.unwrap();

    println!("mode  {}", version.mode);
    println!("major {}", version.major);
    println!("minor {}", version.minor);
    println!("patch {}", version.patch);

    assert_eq!(version.major, 0x00);
    assert_eq!(version.minor, 0x00);
    assert!(version.patch >= 0x02);
}

#[tokio::test]
#[serial]
async fn address() {
    let app = app();
    let path = BIP44Path{path: "m/44'/877'/0/0/0".to_string()};

    let show_on_screen = false;
    let response = app.get_address_and_pubkey(&path, show_on_screen).await.unwrap();


    let expected_pubkey = "f2f44a2f95ed3b2024e3b73a803084e1df8caaecd5f39f5f62ebc99d66fd6edf";
    let expected_address = "atest1d9khqw36gvu5zwpjxppnvvfngverjdf4xaznxdzpxquyzvpsgv6rgvpcxqcyy32ygcmy2wpcysxzwu";

    assert_eq!(
        ED25519_PUBKEY_LEN,
        response.public_key.len()
    );

    assert_eq!(
        hex::encode(&response.public_key),
        expected_pubkey
    );
    assert_eq!(
        response.address_str,
        expected_address
    );

    println!("Public Key  {:?}", hex::encode(&response.public_key));
    println!("Address Byte Format  {:?}", hex::encode(&response.address_bytes));
    println!("Address String Format  {:?}", response.address_str);
}

#[tokio::test]
#[serial]
async fn sign_verify() {
    let app = app();

    // Transaction blob
    let blob_hex_string = "1e0000006532652d746573742e6563353631326230393430336233333238396463380023000000323032332d30362d31335431383a30343a32392e3034353635373838352b30303a3030b35e401c64e395bf63d729dcfb2b6c6f180e0fd7959f232d3c7a9b6ee19ffaf43a3cde6c93bbe91ba1cbf4c48583a7d0b6bcbd4edf665491079bf8e1a6bb3de60100e1f5050000000000280000003442383846423931334130373636453330413030423246423841413239343941373130453234453600d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a01000000000000000000000000000000000500000000f53beeb5880100009200000000280000004345463235443836434144434442393646313238454431364444464142353331443334373145324500280000003032413641313942313533413738303631463237373539393032383046354337353241464633354300280000003344323334443145333945313831443532443031383036354531343243413931433035324245334500c0f35e0100000000000002f53beeb58801000000eb0ade49c13ca12b3b824c67c481f86a36536f56884bef664f2b065ceca9e1c603f63beeb5880100003a3cde6c93bbe91ba1cbf4c48583a7d0b6bcbd4edf665491079bf8e1a6bb3de60037743f9803487346da353af25536ef143c74365c797d8dc5373392e4e275706410a64b0ea0c62f3e3a77653bb90e4f3c25fdacf564c14a52407470efe3929e0000d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a03f73beeb588010000b35e401c64e395bf63d729dcfb2b6c6f180e0fd7959f232d3c7a9b6ee19ffaf4009d916591238563bceed4014ee0a20b7ea0d16e4ea3da97768e44748f0dd7e10a47e741b0fcea1f414970437848d532914a7ffb72982382c158d9f9eaa38af50300d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a038c3ceeb58801000042017852d71ee84ec043d5f1d8e83ccf2b348ba011e75d9c0b41db560748cc6f00aaf51f89bed31127e836a6e9a5f0472fb0439d670d3ed49f9c79021d769ff06fe2820c26a0b452505a3cff3615995c69d72bfa9181ecb5ec50bb942c625c1a0500d04d39252f8f76ee4ce7ff1ce846f45d9bb0aa4b84e10e7ee96382958f4c9d3a".as_bytes();
    let blob = Vec::from_hex(blob_hex_string).expect("Invalid hexadecimal string");

    // Hashes for signature verification
    let header_hash_hex_string = "8e4dd77127cc886afaf406608557297b79fc3723787321e599def50921a369a6".as_bytes();
    let header_hash = Vec::from_hex(header_hash_hex_string).expect("Invalid hexadecimal string");
    let data_hash_hex_string = "3a3cde6c93bbe91ba1cbf4c48583a7d0b6bcbd4edf665491079bf8e1a6bb3de6".as_bytes();
    let data_hash = Vec::from_hex(data_hash_hex_string).expect("Invalid hexadecimal string");
    let code_hash_hex_string = "b35e401c64e395bf63d729dcfb2b6c6f180e0fd7959f232d3c7a9b6ee19ffaf4".as_bytes();
    let code_hash = Vec::from_hex(code_hash_hex_string).expect("Invalid hexadecimal string");

    let path = BIP44Path{path: "m/44'/877'/0/0/0".to_string()};
    let show_on_screen = false;
    // First, get public key
    let response_address = app.get_address_and_pubkey(&path, show_on_screen).await.unwrap();

    // Sign and retrieve signatures
    let response = app.sign(&path, &blob).await.unwrap();

    // Verify signatures
    let header_signature_ok = app.verify_signature(&response.header_signature, &header_hash, &response_address.public_key);
    let data_signature_ok = app.verify_signature(&response.data_signature, &data_hash, &response_address.public_key);
    let code_signature_ok = app.verify_signature(&response.code_signature, &code_hash, &response_address.public_key);
    let signature_ok = header_signature_ok && data_signature_ok && code_signature_ok;

    assert_eq!(
        signature_ok,
        true
    );
}
