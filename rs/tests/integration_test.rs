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

use hex::FromHex;
use ledger_namada_rs::{BIP44Path, NamadaApp, PK_LEN_PLUS_TAG};
use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
use once_cell::sync::Lazy;
use serial_test::serial;
use std::collections::HashMap;

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
    let path = BIP44Path {
        path: "m/44'/877'/0'/0'/0'".to_string(),
    };

    let show_on_screen = true;
    let response = app
        .get_address_and_pubkey(&path, show_on_screen)
        .await
        .unwrap();

    let expected_pubkey = "0039c1a4bea74c320ab04be5b218369d8c1ae21e41f27edee173ce5e6a51015a4d";
    let expected_address = "tnam1qq6qyugak0gd4up6lma8z8wr88w3pq9lgvfhw6yu";

    assert_eq!(PK_LEN_PLUS_TAG, response.public_key.len());

    assert_eq!(hex::encode(&response.public_key), expected_pubkey);
    assert_eq!(response.address_str, expected_address);

    println!("Public Key  {:?}", hex::encode(&response.public_key));
    println!(
        "Address Byte Format  {:?}",
        hex::encode(&response.address_bytes)
    );
    println!("Address String Format  {:?}", response.address_str);
}

#[tokio::test]
#[serial]
async fn sign_verify() {
    let app = app();

    // Bond transaction blob
    let blob_hex_string = "1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a31322e3030383437393437392b30303a303029e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca0048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80300000000000000a861000000000000000200000002b3078bd88b010000007c7a739c83e943d4a56a0fd4e4c52a9edc0d66d9105324bcc909619857a6683b010c00000074785f626f6e642e7761736d00b3078bd88b0100004b00000000f2d1fbf5a690f8ab12cfa6166425bec4d7569bb400e9a435000000000000000000000000000000000000000000000000000000000100ba4c9645a23343896227110a902af84e7b4a4bb3".as_bytes();
    let blob = Vec::from_hex(blob_hex_string).expect("Invalid hexadecimal string");

    let mut section_hashes: HashMap<usize, Vec<u8>> = HashMap::new();
    section_hashes.insert(
        0,
        hex::decode("5b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b2965013742").unwrap(),
    );
    section_hashes.insert(
        1,
        hex::decode("29e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58").unwrap(),
    );
    section_hashes.insert(
        2,
        hex::decode("f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be").unwrap(),
    );
    section_hashes.insert(
        0xff,
        hex::decode("c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e0").unwrap(),
    );

    let path = BIP44Path {
        path: "m/44'/877'/0'/0'/0'".to_string(),
    };
    let show_on_screen = false;
    // First, get public key
    let response_address = app
        .get_address_and_pubkey(&path, show_on_screen)
        .await
        .unwrap();

    // Sign and retrieve signatures
    let response = app.sign(&path, &blob).await.unwrap();
    let signature_ok =
        app.verify_signature(&response, section_hashes, &response_address.public_key);

    assert_eq!(signature_ok, true);
}
