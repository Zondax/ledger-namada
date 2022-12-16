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
#include <hexutils.h>
#include "crypto_helper.h"

using namespace std;
struct AddressTestcase {
        string pubkey;
        string address;
};

TEST(Address, NamadaEncodingTestnet) {
        vector<AddressTestcase> testnet_addresses {
                {"f2ae0543cc0d223dd94d25a480e69d1f8281af1b1d9be5a37948fb6a084952bf", "atest1d9khqw36ggurxwzzxsurxdpkx4q5gdzzg5urvvjxxdpyvd33xv6rwvp5g4znjvpnxazrzvjxf6htp5"},
                {"d1b7bf436f5be86b1bd4bfeb69d6b89c3e5fb8b5a7fa1960f9444d1f230514a3", "atest1d9khqw36xuunsvzzxgeyvs3cxumyv3j9xgc52s2zgvmry3f5gseygdjygs6nqsfnxcmyywfclfh7pk"},
                {"b3b2249409de8726a947263e54d71732609c0418faa4a31e9191339ee24a6df3", "atest1d9khqw36gg65gd35xqmnvvphg565ydjxx5mrqdjyxu65ydp5xeprxs6y8ppr2wzp8qerqwzpm8c7c6"},
                {"65f6d36aaec57a023a27985b29c2ce11b134a1e1b0fda5f92427cc70268a1d92", "atest1d9khqw36xcmnq3jpggcngdzygcerz3fh8qmnydjzg4znwse3gv6nvdf4x3znqdengsunvsf4rddx0k"},
                {"c10fa512e70013a11caa232827b42ff9ffd7e0b7555af4ed673c823d24a4dc5d", "atest1d9khqw368qc52sjyx9qny3fkg5e5vvfexdq52d6pg3z5xvjzg3pyy3f3xerrj3f5x5enqs2ra8m6n4"},
                {"6d0accf8db1c7ab9bcc4f402398162ad9cf657c1dfdee6c8dcc498f6434dc9f9", "atest1d9khqw36xqur2w2zgvcnxs29xppn2s2zxpprj32zxppnwwfsxu6rg33jg5mnxw2xgdzrxvzzprkw5t"},
                {"c030114335f22bc23dba59b2f7f3e7f80f43536514365479db4a13613bb7fac1", "atest1d9khqw368ye5x3zzx3q5xvjx8quyxvpnxge5gv6yxvmnwv3sgc6y2w2ygfz5xvf5xez52d2p8g08r0"},
                {"8276a5bef2e7f4d1b2a71c0b23dbf9df3bcf2d46155196b30a9ed3b302cbb1ec", "atest1d9khqw36xppr23jyg3ry2ve4g4z5233exg6nqsj9xce5gdz9xaz5zw2yxge5z335g9pnjvpjedjh0n"},
                {"d72c5f56535aec8a9e87c8b4a2e26b4eccdb76e35c68f09b6ce72072a37dcec3", "atest1d9khqw36g5myxv33g5c52vjzxycyzvp4xfryy32rxg6ngsfexvcrzdfsx5erw32rg5eygs3s37h6t7"},
                {"95c4389f19cb90cddbbba24188ec147c53f4c9bab26eeddd23ee17697510db9e", "atest1d9khqw36g5unyd2yxppnzsec8qmn2vzxggm5vd6rxyeyzse5xye5xwfjx3zrw3zpxary2dfkkkftt3"},
                {"1575c42c4a46972fb69624c3c64fa46fa717b3f81fc91a0a793240f462ed1782", "atest1d9khqw36gs6rsdf389rrwvekg9z5gsjxxc6rj3p58qcrxd3exgenz335xcurjsenxeznxwfcdpmvre"},
                {"06b2b0e7100f26c280cf9081f7bd50d02b21cf9e1af8c746b57aba13462cbe82", "atest1d9khqw36g9p5xvjxxgenjsfk8pq52vphxsenjdpexqc5v3f5xvcyvs3cxqmngdzyxsunswpc2gzakw"},
                {"3a7da3dda3d27f7d7115bc0cbd9e7ae2ecb819d88d482190d4452d47c8b85e66", "atest1d9khqw36g4zrqvfsgs6ygde3gvmyvs35gsmnyvfngdrrqsecxvuy2dpcxumygs2rg5urqdjxdpfufc"},
                {"549f986e27d3cbfbd5d9b22adb3d94ccef39a34be552c172347c2e511caf9a23", "atest1d9khqw368prrzvpegccyg3jpxfp5yvps89pnzdjzxs6yzwfhgvmnzdps89qn2s6pgc65gs6zszhqhp"},
                {"55e7670f076faa9012be60d0fcb2f7091d6a603b70fcc565a6f20b4376c912b0", "atest1d9khqw36gsersvf3g5cyvs2ygfry23p4g4pyg3f38qerq3zr8ppyvvfcxgen2d3kgcmryvjz96pmgv"},
                {"7349549a321668d67deab2bef9fc3aeedda31b1b3f8a1602db3d01e163d0664e", "atest1d9khqw36xucyyvejxcmnsvp5xaznjwfhxyunsvjpxdqny3zygvenjse3xsm5xdjr8quyy3z9sny6qs"},
                {"0b70d5d5da0d1f03165daa5463c827a6e0d0fd90736f474410dc98b56eb4a723", "atest1d9khqw36gsm5x3fsxvcnzs6rgyc5zwpsggcrgsjpgfry2v6y8y6nx3zpgvm5xwzpgcey2se5ypzn72"},
                {"80acb673344e74166831ec7bfc7716ddb832469556540c477ddbfd4d327e48fe", "atest1d9khqw36x3q5yv3sxvmrgv6zxcmygwzrg56rqd3kgv6rx3fkgycrxs6px3rrx32rg56rxs6yvqep3p"},
                {"f71954a6053d82121c2ae0acabbaaa7aa66c1ae0a1bbce12458bfbaf5c42d1da", "atest1d9khqw36xerrx3p58ppyyvp3gvuyzsehx3z5gs2ygdpnxdp4xver2v3sx5m5xvfjxpz52v3st7yg5s"},
                {"148d5b752232a584347e3563449f6c91addf284ea280ef7b44cdac4a7c735681", "atest1d9khqw36g4pyy3f5g5unwwfsgve5zdec8qurx3fkx9prydphxymrgvekxpzy2vpexfpnqv2pql96gx"},
                {"ab1b584e7b41fd272e7110d21e81f2c623cd2e41d29116473c505848729a0caf", "atest1d9khqw36gsurw33sgfprwdj9xseny3p4ggcyg33jgsun2sf5x5cr2333xs6nsvp4g4pnydpex703sg"},
                {"3f4e6bba486d51444814aa2422e654f401ec18c158c1db10817c4071fea3e04b", "atest1d9khqw36xv6n2sfcg9znqsec8y6yxwzzx3zyyd3exgcy2desxeryv32px9zrwdpjxerryvzx8wl6xk"},
                {"7c0e7deadb1ab15a5f1d937e279fef7daf174d3b02809806d62e9f233157904c", "atest1d9khqw36xceyzv69g4zrsv3cg5m5zd2pgdzy233jgvunyvf5gezrqd6yg5cnvd3sgv6y23f4q7k3js"},
                {"f9bc8f13609ce609441fbee7d6e2f15fe2e59c0d120714204372c744d3149130", "atest1d9khqw36xcenjdp5g9pr2df4xyunj3zygyerx3phgse5z3ph89zrjve3gyun2334g56r2s3jmkel8c"},
                {"d90a7292de4cdc62b05540170d1f02042e3fdc84177799360791293e3049cc7e", "atest1d9khqw36xvurgvf3gs65y3f3x56y2s298pzrjvj9x3pnxv6z8qe5vvphg3zrydpjxvergvpsk6p52e"},
        };

        const uint8_t NAMADA_ADDRESS_SIZE {84};
        for (const auto& testcase : testnet_addresses) {
                uint8_t pubkey[100] = {0};
                auto bufferLen = parseHexString(pubkey,
                                                sizeof(pubkey),
                                                testcase.pubkey.c_str());

                uint8_t actualAddress[NAMADA_ADDRESS_SIZE] = {0};
                const uint8_t address_len = crypto_encodePubkey_ed25519(actualAddress, sizeof(actualAddress), pubkey, true);
                EXPECT_EQ(address_len, NAMADA_ADDRESS_SIZE);

                const string namada_address(actualAddress, actualAddress + NAMADA_ADDRESS_SIZE);
                EXPECT_EQ(namada_address, testcase.address);
        }
}
