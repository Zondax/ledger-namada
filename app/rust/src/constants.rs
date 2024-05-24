/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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

use jubjub::{AffineNielsPoint, AffinePoint, Fq};

pub const SPENDING_KEY_GENERATOR: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0xec75_293d_8124_8452,
        0x39f5_b033_80af_6020,
        0xf831_c2b1_9fec_6026,
        0x5b38_9522_a9e8_1532,
    ]),
    Fq::from_raw([
        0x14b6_2623_a186_b4b1,
        0x2012_d031_f624_fd52,
        0x75de_fecf_f1f4_9ef2,
        0x0cbc_5f9f_1e52_e0ab,
    ]),
)
.to_niels();

pub const PROOF_GENERATION_KEY_GENERATOR: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x5f3c_723a_a253_1b66,
        0x1e24_f832_67f1_5abd,
        0x4ba1_f065_e719_fd03,
        0x4caa_eaca_af28_ed4b,
    ]),
    Fq::from_raw([
        0xfe6f_96be_c575_bff8,
        0x36b4_9c71_a2af_0708,
        0xc654_dfdd_3600_4de9,
        0x0093_0d67_d690_6365,
    ]),
)
.to_niels();


pub const VALUE_COMMITMENT_RANDOMNESS_GENERATOR: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0xdd93d364cb8cec7e,
        0x91cc3e3835675450,
        0xcfa86026b8d99be9,
        0x1c6da0ce9a5e5fdb,
    ]),
    Fq::from_raw([
        0x28e5fce99ce692d0,
        0xf94c2daa360302fe,
        0xbc900cd4b8ae1150,
        0x555f11f9b720d50b,
    ]),
)
.to_niels();

pub const DIV_SIZE:             usize = 11;
pub const DIV_DEFAULT_LIST_LEN: usize = 4;
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"MASP__gd";
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";
