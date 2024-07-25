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
#include "bech32_encoding.h"
#include <zxmacros.h>

#define MAX_SIZE 280

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25u;
    return ((pre & 0x1FFFFFFu) << 5u) ^
           (-((b >> 0u) & 1u) & 0x3b6a57b2UL) ^
           (-((b >> 1u) & 1u) & 0x26508e6dUL) ^
           (-((b >> 2u) & 1u) & 0x1ea119faUL) ^
           (-((b >> 3u) & 1u) & 0x3d4233ddUL) ^
           (-((b >> 4u) & 1u) & 0x2a1462b3UL);
}

static uint32_t bech32_final_constant(bech32_encoding enc) {
    if (enc == BECH32_ENCODING_BECH32) return 1;
    if (enc == BECH32_ENCODING_BECH32M) return 0x2bc830a3;
    return 0;
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int bech32_encode_large(char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc) {
    uint32_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        char ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = bech32_polymod_step(chk) ^ (ch >> 5u);
        ++i;
    }
    if (i + 7 + data_len > 2*MAX_SIZE) return 0;
    chk = bech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = bech32_polymod_step(chk) ^ (*hrp & 0x1fu);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5u) return 0;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= bech32_final_constant(enc);
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5u - i) * 5u)) & 0x1fu];
    }
    *output = 0;
    return 1;
}

static int convert_bits(uint8_t* out, size_t* outlen, int outBits, const uint8_t* in, size_t inLen, int inBits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1u) << outBits) - 1u;
    while (inLen--) {
        val = (val << inBits) | *(in++);
        bits += inBits;
        while (bits >= outBits) {
            bits -= outBits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outBits - bits)) & maxv;
        }
    } else if (((val << (outBits - bits)) & maxv) || bits >= inBits) {
        return 0;
    }
    return 1;
}

zxerr_t bech32EncodeFromLargeBytes(char *out,
                              size_t out_len,
                              const char *hrp,
                              const uint8_t *in,
                              size_t in_len,
                              uint8_t pad,
                              bech32_encoding enc) {
    MEMZERO(out, out_len);

    if (in_len > MAX_SIZE) {
        return zxerr_out_of_bounds;
    }

    // We set a lower bound to ensure this is safe
    if (out_len < MAX_SIZE) {
        return zxerr_buffer_too_small;
    }

    // Overestimate required size *2==(8/4) instead of *(8/5)
    uint8_t tmp_data[280];
    size_t tmp_size = 0;
    MEMZERO(tmp_data, sizeof(tmp_data));

    convert_bits(tmp_data, &tmp_size, 5, in, in_len, 8, pad);
    if (tmp_size >= out_len) {
        return zxerr_out_of_bounds;
    }

    int err = bech32_encode_large(out, hrp, tmp_data, tmp_size, enc);
    if (err == 0) {
        return zxerr_encoding_failed;
    }

    return zxerr_ok;
}
