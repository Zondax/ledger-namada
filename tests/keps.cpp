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
#include <hexutils.h>

#include <iostream>
#include <vector>

#include "crypto_helper.h"
#include "crypto.h"
#include "gmock/gmock.h"
#include "keys_def.h"
#include "parser_txdef.h"
#include "rslib.h"

using namespace std;
struct NamadaKeys {
  string ask;
  string nsk;
  string ovk;
  string dk;
  string ak;
  string nk;
  string ivk;
  string d0;
  string cv;
};

struct NamadaSignatures {
  string r;
  string rbar;
  string s;
  string sbar;
  string rsk;
  string rk;
};

string toHexString(const uint8_t* data, size_t length) {
  std::stringstream hexStream;
  hexStream << std::hex << std::setfill('0');
  for (size_t i = 0; i < length; ++i) {
    hexStream << std::setw(2) << static_cast<int>(data[i]);
  }
  return hexStream.str();
}

NamadaKeys tv_not_hardened = {
    "ac4da2a5e0a5e3ec2dcbd704f1b08d850fe140ea61072ce3f870e270aecd8f05",
    "47293fb1e93a8663f9a9125652b6dc3d561789c03b674a4cc738a9249aaf0809",
    "cf6bedb6c5494ebab77f58a8573559c5d2683a25224649cb8d4480e8a05458d6",
    "abcb9e0a9bb077b434506896de929a7ac37feaa81bec17e03b60d0605ef7bc42",
    "f65d7b4ab9715c07c6b78bd822ac39a78481eb36079d06dc8679daabab920055",
    "2b41553f32a2b660e1726c313319d35533166ccf52c15ac23cbde3d20d55cb01",
    "8c90b787364dd12911b64b1ebf8bfc04bdc55f97ae851eb3962775564242a102",
    "993f455b74159e49f9cf33",
    "739683cbda183c651ac3db8cc55bac1d179c7f0efa09bf64484120168705f4a5"
};

NamadaSignatures values = {
  "9357809b6204808e81dbed2d3327d4a84f23737ebb4136e915c7e8d287be4a01",
  "d7fbecb584e158c90a02d5ff5914ec729f86f119cee9ed03d1c3af438b30e333",
  "9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a",
  "9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a",
  "740df06d1f775171de02f581aee30fce6c055e54a1c453e6f0f388471026ff05",
  "1918284580da467e5ec723ba86c345cdebf33e882b5c33702804799ac0393802"
};

TEST(Keys, AK_NK_IVK_NON_HARDENED) {

    keys_t keys;
    // Genereric seed from os_derive_bip32_with_seed_no_throw
    uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    // Get master spending key
    // master secret key sk = tmp[..32]
    // chain = tmp[32..]
    uint8_t masterSpendingKey[64] = {0};
    ASSERT_EQ(computeMasterFromSeed(seed, masterSpendingKey), parser_ok);
    memcpy(keys.spendingKey, masterSpendingKey, 32);

    // Compute ask, nsk, ovk
    ASSERT_EQ(convertKey(keys.spendingKey, MODIFIER_ASK, keys.ask, true), parser_ok);
    const string ask_str = toHexString(keys.ask, sizeof(keys.ask));
    EXPECT_EQ(ask_str, tv_not_hardened.ask);

    ASSERT_EQ(convertKey(keys.spendingKey, MODIFIER_NSK, keys.nsk, true), parser_ok);
    const string nsk_str = toHexString(keys.nsk, sizeof(keys.nsk));
    EXPECT_EQ(nsk_str, tv_not_hardened.nsk);

    ASSERT_EQ(convertKey(keys.spendingKey, MODIFIER_OVK, keys.ovk, false), parser_ok);
    const string ovk_str = toHexString(keys.ovk, sizeof(keys.ovk));
    EXPECT_EQ(ovk_str, tv_not_hardened.ovk);

    // Compute diversifier key - dk
    ASSERT_EQ(convertKey(masterSpendingKey, MODIFIER_DK, keys.dk, false), parser_ok);
    const string dk_str = toHexString(keys.dk, sizeof(keys.dk));
    EXPECT_EQ(dk_str, tv_not_hardened.dk);

    // NOT Hardened
    // compute fvk ak+nk+ovk
    // compute ak
    generate_key(keys.ask, SpendingKeyGenerator, keys.ak);
    const string ak_str = toHexString(keys.ak, sizeof(keys.ak));
    EXPECT_EQ(ak_str, tv_not_hardened.ak);

    // compute nk
    uint8_t nk[32] = {0};
    generate_key(keys.nsk, ProofGenerationKeyGenerator, keys.nk);
    const string nk_str = toHexString(keys.nk, sizeof(keys.nk));
    EXPECT_EQ(nk_str, tv_not_hardened.nk);

    // compute ivk
    computeIVK(keys.ak, keys.nk, keys.ivk);
    const string ivk_str = toHexString(keys.ivk, 32);
    EXPECT_EQ(ivk_str, tv_not_hardened.ivk);

    // compute diversifier d0
    uint8_t di[11] = {0};
    uint8_t d_index[11] = {0};
    computeDiversifier(keys.dk, d_index, di);
    const string d0_str = toHexString(di, 11);
    EXPECT_EQ(d0_str, tv_not_hardened.d0);
  }

TEST(Keys, ADDRESS_NON_HARDENED) {

    keys_t keys;

    // TEST ADDRESS
    uint8_t ivk[32] = {
                0xdf, 0x4a, 0xfb, 0x34, 0x37, 0x3a, 0x88, 0x4f, 0x8d, 0x86, 0x53, 0x5a, 0x2c, 0x45,
                0xd6, 0xd3, 0x21, 0x66, 0x9e, 0xbf, 0xb8, 0x59, 0x99, 0x03, 0xa6, 0x40, 0x7d, 0xd3,
                0x82, 0x09, 0x76, 0x01
    };

    const uint8_t default_d[11] = {
                0xa1, 0xe0, 0xf5, 0x3c, 0x47, 0x3e, 0xd9, 0x8c, 0x17, 0xb6, 0xd0
    };

    const uint8_t default_pkd[32] = {
            0xb3, 0x23, 0xbb, 0x8b, 0x98, 0x03, 0x11, 0x44, 0x88, 0x26, 0x0f, 0x9f, 0x51, 0xe5,
            0x46, 0xc2, 0xb4, 0x5f, 0x3d, 0x03, 0x6d, 0x03, 0x9b, 0x0f, 0x0c, 0xb2, 0x86, 0x13,
            0x9d, 0x4c, 0x25, 0xb5
    };

    uint8_t address[32] = {0};
    computePkd(ivk, default_d, address);
    const string addr_str = toHexString(address, 32);
    const string testvector_addr = toHexString(default_pkd, 32);
    EXPECT_EQ(addr_str, testvector_addr);
}

TEST(Keys, COMPUTE_CV) {

    uint64_t value = 74;
    uint8_t rcv[32] = {
        0x6b, 0xb4, 0xa0, 0x7b, 0x8e, 0x82, 0x61, 0x2b, 0x93, 0xef, 0x5c, 0xe1, 0xd5, 0x8f, 0x62, 0x4b, 0xec, 0x77, 0xd6, 0x8b, 0xd4, 0x83, 0xc9, 0xff, 0x5d, 0x12, 0xf1, 0xc0,
        0xef, 0xa4, 0x6f, 0x08
    };
    uint8_t identifier[32] = {
      0xD4, 0xAB, 0x86, 0x5E, 0xD9, 0xFA, 0x5E, 0xC5, 0x22, 0xC7, 0xED, 0x2C, 0xF1, 0xEC, 0x0F, 0xE8,
      0xC6, 0x77, 0xD8, 0xF9, 0x4B, 0xEC, 0x4A, 0x15, 0x78, 0xF0, 0x28, 0x10, 0x0A, 0x2F, 0xF2, 0xE1
    };

    uint8_t cv[32] = {0};
    computeValueCommitment(value, rcv,identifier, cv);
    const string cv_str = toHexString(cv, sizeof(cv));
    EXPECT_EQ(cv_str, tv_not_hardened.cv);
}

/* Signing Computatino TestVectors
apply_signatures: sighash_bytes: 69475d2b9988040d4e76b4dde81954ab54afc54affc6f48e93a618dbc0c21015
sign: t: 029265371f023246969c03e03eaf10b1cd6891f16946f83cbe0ec29e4b75308274227ca381f5c509f6b28cd66c677186f1b6455f3079dc5e26cd6c5341bf4d5bf217c1bb442c0cfa847fbd59254730f2
sign: r: c930e9c67af6f9c1c9cbd2b6f019f813ff5576657c84239215cfbae3b6051f04
sign: r_g: b2f073645fb16a3c0c1144340da27caa64ede92551e6bf8bf5dc2f392f2d49d6
sign: rbar: b2f073645fb16a3c0c1144340da27caa64ede92551e6bf8bf5dc2f392f2d49d6
sign: H*(Rbar || M): 769765eb80953697dd81efc724a3521f7da08b114ce1206906263bcb38244e00
sign: s: 467856038ac43b5fcb6da494e26d7375456d1083215a7257fb556062ec4b4408
sign: sbar: 467856038ac43b5fcb6da494e26d7375456d1083215a7257fb556062ec4b4408
spend_sig_internal: ask: 0cd47b62dea686adfd1e96f6503216cdf133e575221400fd65eeaa378f3d450b
spend_sig_internal: ar: 1f666be29fde619463f42658f1d161a77b0caddf7febbaef33b511756b9d3709
spend_sig_internal: sighash: 69475d2b9988040d4e76b4dde81954ab54afc54affc6f48e93a618dbc0c21015
spend_sig_internal: rsk: 740df06d1f775171de02f581aee30fce6c055e54a1c453e6f0f388471026ff05
spend_sig_internal: rk: 1918284580da467e5ec723ba86c345cdebf33e882b5c33702804799ac0393802
spend_sig_internal: data_to_be_signed: 1918284580da467e5ec723ba86c345cdebf33e882b5c33702804799ac039380269475d2b9988040d4e76b4dde81954ab54afc54affc6f48e93a618dbc0c21015
sign: t: 05734daa7328fa0c91a33d78b9c256c06d79b4b38fa01658d6e3c39781464323d166c95227c2fe5e121e87f7d5d82f712bf0f7a3fa23585543201936370b4562ae3a6604e1870c67cf232bc48fbe39ba
sign: r: 9357809b6204808e81dbed2d3327d4a84f23737ebb4136e915c7e8d287be4a01
sign: r_g: d7fbecb584e158c90a02d5ff5914ec729f86f119cee9ed03d1c3af438b30e333
sign: rbar: d7fbecb584e158c90a02d5ff5914ec729f86f119cee9ed03d1c3af438b30e333
sign: H*(Rbar || M): f133d071d7477f9bb510b74a7c9740db20605a58208d99bcb8eb12ca995edb06
sign: s: 9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a
sign: sbar: 9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a
Personalization Prefix: 5a636173685478486173685f
Consensus Branch ID: MASP
Consensus Branch ID: 3925833126
Personal: 5a636173685478486173685fa675ffe9
Header Digest: Hash(0x0d28515245442c4f2d26f7f584a8a8f6a05a523ed1e76889a521f827187e3e2c)
Transparent Digest: Hash(0xc33f2e95705faab35f8d533fa61e95c3b7aaba0776b874a9f74fc12784376a59)
Sapling Digest: 1ab0d393f113f6ea8a73914bbede894a9ee55405b9f0370efab29cede1f13780
TxId Digest: 1510c2c0db18a6938ef4c6ff4ac5af54ab5419e8ddb4764e0d0488992b5d4769
*/

TEST(Keys, COMPUTE_RBAR_SBAR) {
  
    uint8_t rsk[32] = {
      0x74, 0x0d, 0xf0, 0x6d, 0x1f, 0x77, 0x51, 0x71, 0xde, 0x02, 0xf5, 0x81, 0xae, 0xe3, 0x0f, 0xce, 0x6c,
      0x05, 0x5e, 0x54, 0xa1, 0xc4, 0x53, 0xe6, 0xf0, 0xf3, 0x88, 0x47, 0x10, 0x26, 0xff, 0x05
    };

    uint8_t t[80] = {
      0x05, 0x73, 0x4d, 0xaa, 0x73, 0x28, 0xfa, 0x0c, 0x91, 0xa3, 0x3d, 0x78, 0xb9, 0xc2, 0x56, 0xc0, 0x6d, 
      0x79, 0xb4, 0xb3, 0x8f, 0xa0, 0x16, 0x58, 0xd6, 0xe3, 0xc3, 0x97, 0x81, 0x46, 0x43, 0x23, 0xd1, 0x66, 
      0xc9, 0x52, 0x27, 0xc2, 0xfe, 0x5e, 0x12, 0x1e, 0x87, 0xf7, 0xd5, 0xd8, 0x2f, 0x71, 0x2b, 0xf0, 0xf7, 
      0xa3, 0xfa, 0x23, 0x58, 0x55, 0x43, 0x20, 0x19, 0x36, 0x37, 0x0b, 0x45, 0x62, 0xae, 0x3a, 0x66, 0x04, 
      0xe1, 0x87, 0x0c, 0x67, 0xcf, 0x23, 0x2b, 0xc4, 0x8f, 0xbe, 0x39, 0xba};

    uint8_t data_to_be_signed[64] = {
      0x19, 0x18, 0x28, 0x45, 0x80, 0xda, 0x46, 0x7e, 0x5e, 0xc7, 0x23, 0xba, 0x86, 0xc3, 0x45, 0xcd, 0xeb,
      0xf3, 0x3e, 0x88, 0x2b, 0x5c, 0x33, 0x70, 0x28, 0x04, 0x79, 0x9a, 0xc0, 0x39, 0x38, 0x02, 0x69, 0x47,
      0x5d, 0x2b, 0x99, 0x88, 0x04, 0x0d, 0x4e, 0x76, 0xb4, 0xdd, 0xe8, 0x19, 0x54, 0xab, 0x54, 0xaf, 0xc5,
      0x4a, 0xff, 0xc6, 0xf4, 0x8e, 0x93, 0xa6, 0x18, 0xdb, 0xc0, 0xc2, 0x10, 0x15};
      
    uint8_t r[32] = {0};
    h_star(t, 80, data_to_be_signed, 64, r);
    const string r_str = toHexString(r, sizeof(r));
    EXPECT_EQ(r_str, values.r);

    uint8_t rbar[32] = {0};
    parser_scalar_multiplication(r, SpendingKeyGenerator, rbar);
    const string r_bar_str = toHexString(rbar, sizeof(rbar));
    EXPECT_EQ(r_bar_str, values.rbar);

    uint8_t s[32] = {0};
    h_star(rbar, 32, data_to_be_signed, 64, s);

    uint8_t sbar[32] = {0};
    parser_compute_sbar(s, r, rsk, sbar);
    const string sbar_str = toHexString(sbar, sizeof(sbar));
    EXPECT_EQ(sbar_str, values.sbar);
};

TEST(Keys, COMPUTE_RSK_RK) {
    uint8_t ask[32] = {
      0x0c, 0xd4, 0x7b, 0x62, 0xde, 0xa6, 0x86, 0xad, 0xfd, 0x1e, 0x96, 0xf6, 0x50, 0x32, 0x16, 0xcd, 0xf1, 0x33, 0xe5, 0x75,
      0x22, 0x14, 0x00, 0xfd, 0x65, 0xee, 0xaa, 0x37, 0x8f, 0x3d, 0x45, 0x0b
    };

    uint8_t ar[32] = {
      0x1f, 0x66, 0x6b, 0xe2, 0x9f, 0xde, 0x61, 0x94, 0x63, 0xf4, 0x26, 0x58, 0xf1, 0xd1, 0x61, 0xa7, 0x7b, 0x0c, 0xad, 0xdf,
      0x7f, 0xeb, 0xba, 0xef, 0x33, 0xb5, 0x11, 0x75, 0x6b, 0x9d, 0x37, 0x09
    };

    uint8_t rsk[32] = {0};
    parser_randomized_secret_from_seed(ask, ar, rsk);
    const string rsk_str = toHexString(rsk, sizeof(rsk));
    EXPECT_EQ(rsk_str, values.rsk);

    uint8_t rk[32] = {0};
    parser_scalar_multiplication(rsk, SpendingKeyGenerator, rk);
    const string rk_str = toHexString(rk, sizeof(rk));
    EXPECT_EQ(rk_str, values.rk);
}
