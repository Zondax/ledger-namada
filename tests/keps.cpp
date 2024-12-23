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

#include "crypto.h"
#include "crypto_helper.h"
#include "gmock/gmock.h"
#include "keys_def.h"
#include "parser_txdef.h"
#include "rslib.h"

using namespace std;

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

NamadaSignatures values = {
    "9357809b6204808e81dbed2d3327d4a84f23737ebb4136e915c7e8d287be4a01",
    "d7fbecb584e158c90a02d5ff5914ec729f86f119cee9ed03d1c3af438b30e333",
    "9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a",
    "9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a",
    "740df06d1f775171de02f581aee30fce6c055e54a1c453e6f0f388471026ff05",
    "1918284580da467e5ec723ba86c345cdebf33e882b5c33702804799ac0393802"};

/* Signing Computatino TestVectors
apply_signatures: sighash_bytes:
69475d2b9988040d4e76b4dde81954ab54afc54affc6f48e93a618dbc0c21015 sign: t:
029265371f023246969c03e03eaf10b1cd6891f16946f83cbe0ec29e4b75308274227ca381f5c509f6b28cd66c677186f1b6455f3079dc5e26cd6c5341bf4d5bf217c1bb442c0cfa847fbd59254730f2
sign: r: c930e9c67af6f9c1c9cbd2b6f019f813ff5576657c84239215cfbae3b6051f04
sign: r_g: b2f073645fb16a3c0c1144340da27caa64ede92551e6bf8bf5dc2f392f2d49d6
sign: rbar: b2f073645fb16a3c0c1144340da27caa64ede92551e6bf8bf5dc2f392f2d49d6
sign: H*(Rbar || M):
769765eb80953697dd81efc724a3521f7da08b114ce1206906263bcb38244e00 sign: s:
467856038ac43b5fcb6da494e26d7375456d1083215a7257fb556062ec4b4408 sign: sbar:
467856038ac43b5fcb6da494e26d7375456d1083215a7257fb556062ec4b4408
spend_sig_internal: ask:
0cd47b62dea686adfd1e96f6503216cdf133e575221400fd65eeaa378f3d450b
spend_sig_internal: ar:
1f666be29fde619463f42658f1d161a77b0caddf7febbaef33b511756b9d3709
spend_sig_internal: sighash:
69475d2b9988040d4e76b4dde81954ab54afc54affc6f48e93a618dbc0c21015
spend_sig_internal: rsk:
740df06d1f775171de02f581aee30fce6c055e54a1c453e6f0f388471026ff05
spend_sig_internal: rk:
1918284580da467e5ec723ba86c345cdebf33e882b5c33702804799ac0393802
spend_sig_internal: data_to_be_signed:
1918284580da467e5ec723ba86c345cdebf33e882b5c33702804799ac039380269475d2b9988040d4e76b4dde81954ab54afc54affc6f48e93a618dbc0c21015
sign: t:
05734daa7328fa0c91a33d78b9c256c06d79b4b38fa01658d6e3c39781464323d166c95227c2fe5e121e87f7d5d82f712bf0f7a3fa23585543201936370b4562ae3a6604e1870c67cf232bc48fbe39ba
sign: r: 9357809b6204808e81dbed2d3327d4a84f23737ebb4136e915c7e8d287be4a01
sign: r_g: d7fbecb584e158c90a02d5ff5914ec729f86f119cee9ed03d1c3af438b30e333
sign: rbar: d7fbecb584e158c90a02d5ff5914ec729f86f119cee9ed03d1c3af438b30e333
sign: H*(Rbar || M):
f133d071d7477f9bb510b74a7c9740db20605a58208d99bcb8eb12ca995edb06 sign: s:
9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a sign: sbar:
9ea71021df2d6f1f8240350026cacf2e36ffeb6dbc2d8202de782a8fdc27b40a Personalization
Prefix: 5a636173685478486173685f Consensus Branch ID: MASP Consensus Branch ID:
3925833126 Personal: 5a636173685478486173685fa675ffe9 Header Digest:
Hash(0x0d28515245442c4f2d26f7f584a8a8f6a05a523ed1e76889a521f827187e3e2c)
Transparent Digest:
Hash(0xc33f2e95705faab35f8d533fa61e95c3b7aaba0776b874a9f74fc12784376a59) Sapling
Digest: 1ab0d393f113f6ea8a73914bbede894a9ee55405b9f0370efab29cede1f13780 TxId
Digest: 1510c2c0db18a6938ef4c6ff4ac5af54ab5419e8ddb4764e0d0488992b5d4769
*/

TEST(Keys, COMPUTE_RBAR_SBAR) {
  uint8_t rsk[32] = {0x74, 0x0d, 0xf0, 0x6d, 0x1f, 0x77, 0x51, 0x71,
                     0xde, 0x02, 0xf5, 0x81, 0xae, 0xe3, 0x0f, 0xce,
                     0x6c, 0x05, 0x5e, 0x54, 0xa1, 0xc4, 0x53, 0xe6,
                     0xf0, 0xf3, 0x88, 0x47, 0x10, 0x26, 0xff, 0x05};

  uint8_t t[80] = {0x05, 0x73, 0x4d, 0xaa, 0x73, 0x28, 0xfa, 0x0c, 0x91, 0xa3,
                   0x3d, 0x78, 0xb9, 0xc2, 0x56, 0xc0, 0x6d, 0x79, 0xb4, 0xb3,
                   0x8f, 0xa0, 0x16, 0x58, 0xd6, 0xe3, 0xc3, 0x97, 0x81, 0x46,
                   0x43, 0x23, 0xd1, 0x66, 0xc9, 0x52, 0x27, 0xc2, 0xfe, 0x5e,
                   0x12, 0x1e, 0x87, 0xf7, 0xd5, 0xd8, 0x2f, 0x71, 0x2b, 0xf0,
                   0xf7, 0xa3, 0xfa, 0x23, 0x58, 0x55, 0x43, 0x20, 0x19, 0x36,
                   0x37, 0x0b, 0x45, 0x62, 0xae, 0x3a, 0x66, 0x04, 0xe1, 0x87,
                   0x0c, 0x67, 0xcf, 0x23, 0x2b, 0xc4, 0x8f, 0xbe, 0x39, 0xba};

  uint8_t data_to_be_signed[64] = {
      0x19, 0x18, 0x28, 0x45, 0x80, 0xda, 0x46, 0x7e, 0x5e, 0xc7, 0x23,
      0xba, 0x86, 0xc3, 0x45, 0xcd, 0xeb, 0xf3, 0x3e, 0x88, 0x2b, 0x5c,
      0x33, 0x70, 0x28, 0x04, 0x79, 0x9a, 0xc0, 0x39, 0x38, 0x02, 0x69,
      0x47, 0x5d, 0x2b, 0x99, 0x88, 0x04, 0x0d, 0x4e, 0x76, 0xb4, 0xdd,
      0xe8, 0x19, 0x54, 0xab, 0x54, 0xaf, 0xc5, 0x4a, 0xff, 0xc6, 0xf4,
      0x8e, 0x93, 0xa6, 0x18, 0xdb, 0xc0, 0xc2, 0x10, 0x15};

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
  uint8_t ask[32] = {0x0c, 0xd4, 0x7b, 0x62, 0xde, 0xa6, 0x86, 0xad,
                     0xfd, 0x1e, 0x96, 0xf6, 0x50, 0x32, 0x16, 0xcd,
                     0xf1, 0x33, 0xe5, 0x75, 0x22, 0x14, 0x00, 0xfd,
                     0x65, 0xee, 0xaa, 0x37, 0x8f, 0x3d, 0x45, 0x0b};

  uint8_t ar[32] = {0x1f, 0x66, 0x6b, 0xe2, 0x9f, 0xde, 0x61, 0x94,
                    0x63, 0xf4, 0x26, 0x58, 0xf1, 0xd1, 0x61, 0xa7,
                    0x7b, 0x0c, 0xad, 0xdf, 0x7f, 0xeb, 0xba, 0xef,
                    0x33, 0xb5, 0x11, 0x75, 0x6b, 0x9d, 0x37, 0x09};

  uint8_t rsk[32] = {0};
  parser_randomized_secret_from_seed(ask, ar, rsk);
  const string rsk_str = toHexString(rsk, sizeof(rsk));
  EXPECT_EQ(rsk_str, values.rsk);

  uint8_t rk[32] = {0};
  parser_scalar_multiplication(rsk, SpendingKeyGenerator, rk);
  const string rk_str = toHexString(rk, sizeof(rk));
  EXPECT_EQ(rk_str, values.rk);
}
