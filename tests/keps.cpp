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
