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
    let path = BIP44Path{path: "m/44'/283'/0/0/0".to_string()};

    let show_on_screen = false;
    let response = app.get_address_and_pubkey(&path, show_on_screen).await.unwrap();


    let expected_pubkey = "3fb471c595c73f9a4f2931ef95673c12fae0bcfc2043df86a346ef128b8541e7";
    let expected_address = "atest1d9khqw36x56rqdzrxcenyd6xggc5xwphxc6rgdzzxce5yd3e8ycyvdj9xgenwve489zygvf5cukn9v";

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

    let code = "WrapperCode".as_bytes();
    let data = "WrapperData".as_bytes();

    let timestamp = prost_types::Timestamp {
        seconds: 1672923381,
        nanos: 536609000,
    };

    let path = BIP44Path{path: "m/44'/283'/0/0/0".to_string()};
    let show_on_screen = false;

    // First, get public key
    let response_address = app.get_address_and_pubkey(&path, show_on_screen).await.unwrap();
    println!("Address String Format  {:?}", response_address.address_str);


    let response = app.sign_wrapper_transaction(&path, &code, &data, &timestamp).await.unwrap();

    let signature_ok = app.verify_wrapper_transaction_signature(code,
                                                                      data,
                                                                      &timestamp,
                                                                      &response_address.public_key,
                                                                      &response.signature);
    assert_eq!(
        signature_ok,
        true
    );
}
