/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

#include "gmock/gmock.h"

#include <vector>
#include <iostream>
#include <cstring>
#include <hexutils.h>
#include "crypto_helper.h"
#include "leb128.h"
#include "bech32.h"

using namespace std;
struct NamAddress {
        string rawPubkey;
        string pubkey;
        string address;
};

struct LEB128Testcase {
        uint64_t input;
        vector<uint8_t> expected;
        uint8_t consumed;
};

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

TEST(AddressMainnet, NamadaEncoding) {
    const vector<NamAddress> addresses = {
        {"00ef4f3e86bda2707e6556d884ee9b84dc638aa66f3e93ba95e1e192201d24df58", "tpknam1qrh5705xhk38qln92mvgfm5msnwx8z4xdulf8w54u8seygqayn04ssjm4fh", "tnam1qznvavtnr32sg6xdjszh6v6v977wx80zrqp92avx"},
        {"00dc9600279f7b74c3a4356d071c09909c18cc4df759163116b85c130bd4f7a368", "tpknam1qrwfvqp8naahfsayx4ksw8qfjzwp3nzd7av3vvgkhpwpxz75773kspcnh4y", "tnam1qpp5g5wg4s9m84mf99dmz7wde4gs6jxe9cegwa6f"},
        {"00182474b6dcfe064f04354cf8481470329a0a0ec99fccffcb467b5b3bc1a7fa28", "tpknam1qqvzga9kmnlqvncyx4x0sjq5wqef5zswex0uel7tgea4kw7p5lazscg77ph", "tnam1qzfg7yxhrx5q0r05hkn9rxagd7tawunl7ygjz4xg"},
        {"00dea5abe6e3eec1201df7c7de4e4516db6c4019255b7a0d42d1c31a19b9e69696", "tpknam1qr02t2lxu0hvzgqa7lraunj9zmdkcsqey4dh5r2z68p35xdeu6tfv7rv94a", "tnam1qq8m3d3ctauwyprmpzm0xcll2rc9dyts6vna7eex"},
        {"00472df7382f98dae10f7f788da4160f5f56a9706875dd62a37bbd8c8fc9f219bf", "tpknam1qprjmaec97vd4cg00augmfqkpa04d2tsdp6a6c4r0w7cer7f7gvm73c8dac", "tnam1qzqfhedk5c60y6mlwms0f2d6e8nry77azyuh698k"},
        {"007c85efea1deb4a98f0a0ff1d479ff2778ef5f02e1166e816701eb13d7e7fe8a4", "tpknam1qp7gtml2rh454x8s5rl363ul7fmcaa0s9cgkd6qkwq0tz0t70l52gk8der2", "tnam1qpuxvln357vmjnzf74qgsgnp8v9mynv60qyaxcg4"},
        {"0030019011e8149b773c89b1ddae91cbd6ec86f2b9b1c4a6af0252d2e51ad2a76c", "tpknam1qqcqryq3aq2fkaeu3xcamt53e0twephjhxcuff40qffd9eg662nkcv5kqks", "tnam1qrlumxt4qkcz9m3ddwmyl34e463dvqh6aqttlpne"},
        {"00e3d1dc9872feb10aca54450ae6393434bb8c0ec9bac5708def4a7c6c12ef2a96", "tpknam1qr3arhycwtltzzk223zs4e3exs6thrqwexav2uydaa98cmqjau4fvd3w7kc", "tnam1qp4lr2nlmy7vqssrtaq75wpsc8z4kmlkes4xvlfd"},
        {"006b1541e97d413c37460467e9f9572bf285ad6a25659297c23def810e94df52d2", "tpknam1qp432s0f04qncd6xq3n7n72h90egttt2y4je997z8hhczr55mafdyqlyjul", "tnam1qq9way96y9te6cjm7gnluz39re8kgw43msx7esrv"},
        {"001372fa6f565c392c874e9455067408ebfabaadabb5d073b50670b7c1d71f1a8b", "tpknam1qqfh97n02ewrjty8f6292pn5pr4l4w4d4w6aqua4qect0swhrudgkeyednn", "tnam1qq4y45pfrp5qpry34vwm9j7yrl227knl2vznvs66"}
    };

    hdPath[1] = HDPATH_1_DEFAULT;

    for (const auto& testcase : addresses) {
        uint8_t rawPubkey[PK_LEN_25519_PLUS_TAG] = {0};
        parseHexString(rawPubkey, sizeof(rawPubkey), testcase.rawPubkey.c_str());

        char pubkey[PUBKEY_LEN_MAINNET + 1] = {0};
        zxerr_t err = crypto_encodeRawPubkey(rawPubkey, sizeof(rawPubkey), (uint8_t*) pubkey, sizeof(pubkey));
        EXPECT_EQ(err, zxerr_ok);

        const uint8_t pubkeyLen = pubkey[0];
        EXPECT_EQ(pubkeyLen, PUBKEY_LEN_MAINNET);
        const string namada_pubkey(pubkey + 1, pubkey + 1 + pubkeyLen);
        EXPECT_EQ(namada_pubkey, testcase.pubkey);


        char address[ADDRESS_LEN_MAINNET + 1] = {0};
        err = crypto_encodeAddress(rawPubkey + 1, PK_LEN_25519, (uint8_t*) address, sizeof(address));
        EXPECT_EQ(err, zxerr_ok);

        const uint8_t addressLen = address[0];
        EXPECT_EQ(addressLen, ADDRESS_LEN_MAINNET);
        const string namada_address(address + 1, address + 1 + ADDRESS_LEN_MAINNET);
        EXPECT_EQ(namada_address, testcase.address);
    }
}

TEST(AddressTestnet, NamadaEncoding) {
    const vector<NamAddress> addresses = {
        {"005816b3661e718d005eb439e762ed33b1d497deb01bbae4cc622e9858db20af62", "testtpknam1qpvpdvmxrecc6qz7ksu7wchdxwcaf977kqdm4exvvghfskxmyzhky7p9ru7", "testtnam1qrvfj5x38gattvnw467vz8vefnqmcxxv2cexrmwe"},
        {"002ed81476c5a379c86df357fc7924e59044dd57d722ab91d99accd145220c3ac5", "testtpknam1qqhds9rkck3hnjrd7dtlc7fyukgyfh2h6u32hywentxdz3fzpsav2aa6yax", "testtnam1qzu7l3lhk5gatgvhwgh64kw5rqgmde5xagnf03xv"},
        {"00709779b9b5642c36b63069ff9fb7e4b745e4d60e804a871f473c5a189bc8edba", "testtpknam1qpcfw7dek4jzcd4kxp5ll8ahujm5texkp6qy4pclgu795xymerkm5z9fms9", "testtnam1qprqd8wfemc7x0yklkm5wgstjtg2cvpstvjglaaw"},
        {"00cfa4036a28d88aa125882912aa484a790d3d836e0188ebeed672947721c5a1f8", "testtpknam1qr86gqm29rvg4gf93q5392jgffus60vrdcqc36lw6eefgaepckslsph9jlw", "testtnam1qrru7wem8djnq3jxpk48ce6ecqgqsppu6qd287m2"},
        {"006c47b14e4ef892b4c639cbf55c6a3433eb5effacc7a164f1321d6f782464a12e", "testtpknam1qpky0v2wfmuf9dxx889l2hr2xse7khhl4nr6ze83xgwk77pyvjsjusxp7mk", "testtnam1qzth3alv0u8w6pte84mek05mq42p2530qqpyvt86"},
        {"00d1337b3e52fbdc91200581a1946117aa0a9204851f7c8592ed38bf67cf37e450", "testtpknam1qrgnx7e72taaeyfqqkq6r9rpz74q4ysys50hepvja5ut7e70xlj9q73a27g", "testtnam1qrsrm5tducka7g9k5jgy6n4uumaeeahdcchz7d7v"},
        {"0053ce80e9a62429a0f1c642b55ea6f425df123f282f2f04164d07edd2a66f3e52", "testtpknam1qpfuaq8f5cjzng83cept2h4x7sja7y3l9qhj7pqkf5r7m54xdul9yd0sp5g", "testtnam1qpwljuwllcwm8gth8jmqmnpv742va9y97uej87m5"},
        {"0084f2a5c5dacb0d554337b803e91d8a2fb0a7d0775d78b32a6792cd862e9f6fd8", "testtpknam1qzz09fw9mt9s642rx7uq86ga3ghmpf7swawh3ve2v7fvmp3wnahasnnvx7j", "testtnam1qzyujwdgln6av7952nrxnwj338kl8xw2dczza0sa"},
        {"003eaf5fe64fe8235a64a1879aaa0ebb2685c1a9220131dd9731e6a9acc650c0e4", "testtpknam1qql27hlxfl5zxkny5xre42swhvngtsdfygqnrhvhx8n2ntxx2rqwgfj964d", "testtnam1qp98248ld824crcv4kadv4gg0flp9zdz6yuhlnl0"},
        {"003a43272baff528f76a07d4cc8aa295939269bda6a95040ac9ddfb674d5d14fdc", "testtpknam1qqayxfet4l6j3am2ql2vez4zjkfey6da5654qs9vnh0mvax4698acnarh59", "testtnam1qrafawzxjaq23u6cwn9tmza7aq2nugpt0qhl4qxj"}
    };

    hdPath[1] = HDPATH_1_TESTNET;

    for (const auto& testcase : addresses) {
        uint8_t rawPubkey[PK_LEN_25519_PLUS_TAG] = {0};
        parseHexString(rawPubkey, sizeof(rawPubkey), testcase.rawPubkey.c_str());

        char pubkey[PUBKEY_LEN_TESTNET + 1] = {0};
        zxerr_t err = crypto_encodeRawPubkey(rawPubkey, sizeof(rawPubkey), (uint8_t*) pubkey, sizeof(pubkey));
        EXPECT_EQ(err, zxerr_ok);

        const uint8_t pubkeyLen = pubkey[0];
        EXPECT_EQ(pubkeyLen, PUBKEY_LEN_TESTNET);
        const string namada_pubkey(pubkey + 1, pubkey + 1 + pubkeyLen);
        EXPECT_EQ(namada_pubkey, testcase.pubkey);


        char address[ADDRESS_LEN_TESTNET + 1] = {0};
        err = crypto_encodeAddress(rawPubkey + 1, PK_LEN_25519, (uint8_t*) address, sizeof(address));
        EXPECT_EQ(err, zxerr_ok);

        const uint8_t addressLen = address[0];
        EXPECT_EQ(addressLen, ADDRESS_LEN_TESTNET);
        const string namada_address(address + 1, address + 1 + ADDRESS_LEN_TESTNET);
        EXPECT_EQ(namada_address, testcase.address);
    }
}

TEST(LEB128, LEB128Encoding) {
        const vector<LEB128Testcase> leb128_encoding {
                {12, {0x0C}, 1},
                {32, {0x20}, 1},
                { 1548174235, {0x9B, 0x87, 0x9D, 0xE2, 0x05, }, 5 },
                { 693000000, {0xC0, 0xAE, 0xB9, 0xCA, 0x02, }, 5 },
                { 1135613917, {0xDD, 0xAF, 0xC0, 0x9D, 0x04, }, 5 },
                { 390000000, {0x80, 0xDB, 0xFB, 0xB9, 0x01, }, 5 },
                { 1150276518, {0xA6, 0xA7, 0xBF, 0xA4, 0x04, }, 5 },
                { 992000000, {0x80, 0xF0, 0x82, 0xD9, 0x03, }, 5 },
                { 1640106391, {0x97, 0x93, 0x88, 0x8E, 0x06, }, 5 },
                { 965000000, {0xC0, 0xF6, 0x92, 0xCC, 0x03, }, 5 },
                { 1002286660, {0xC4, 0xDC, 0xF6, 0xDD, 0x03}, 5 },
                { 308000000, {0x80, 0xEA, 0xEE, 0x92, 0x01}, 5 },
        };

        for (const auto& testcase : leb128_encoding) {
                uint8_t encoded[MAX_LEB128_OUTPUT] = {0};
                uint8_t bytes = 0;
                const zxerr_t err = encodeLEB128(testcase.input, (uint8_t*) &encoded, MAX_LEB128_OUTPUT, &bytes);

                ASSERT_EQ(err, zxerr_ok);
                ASSERT_EQ(testcase.consumed, bytes);

                EXPECT_TRUE(memcmp(testcase.expected.data(), &encoded, bytes) == 0);
        }
}
