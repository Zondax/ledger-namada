/*******************************************************************************
 *   (c) 2018 -2022 Zondax AG
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

#include "nvdata.h"
#include "coin.h"
#include "constants.h"
#include "cx.h"
#include "os.h"
#include "view.h"

transaction_info_t NV_CONST N_transaction_info_impl __attribute__((aligned(64)));
#define N_transactioninfo                                                      \
  (*(NV_VOLATILE transaction_info_t *)PIC(&N_transaction_info_impl))

zxerr_t transaction_add_sizes(uint8_t n_spends, uint8_t n_outputs,
                                 uint8_t n_converts) {
    MEMCPY_NV((void *)&N_transactioninfo.n_spends, &n_spends, sizeof(uint8_t));
    MEMCPY_NV((void *)&N_transactioninfo.n_outputs, &n_outputs, sizeof(uint8_t));
    MEMCPY_NV((void *)&N_transactioninfo.n_converts, &n_converts, sizeof(uint8_t));
    return zxerr_ok;
}

zxerr_t transaction_append_spend_rcv(uint8_t i, uint8_t *rcv) {
    if (i >= N_transactioninfo.n_spends) {
        return zxerr_out_of_bounds;
    }

    MEMCPY_NV((void *)&N_transactioninfo.spends[i].rcv, rcv, 32);
    return zxerr_ok;
}

zxerr_t transaction_append_spend_alpha(uint8_t i, uint8_t *alpha) {
    if (i >= N_transactioninfo.n_spends) {
        return zxerr_out_of_bounds;
    }

    MEMCPY_NV((void *)&N_transactioninfo.spends[i].alpha, alpha, 32);
    return zxerr_ok;
}

zxerr_t transaction_append_output_rcv(uint8_t i, uint8_t *rcv) {
    if (i >= N_transactioninfo.n_outputs) {
        return zxerr_out_of_bounds;
    }

    MEMCPY_NV((void *)&N_transactioninfo.outputs[i].rcv, rcv, 32);
    return zxerr_ok;
}

zxerr_t transaction_append_output_rcm(uint8_t i, uint8_t *rcm) {
    if (i >= N_transactioninfo.n_outputs) {
        return zxerr_out_of_bounds;
    }

    MEMCPY_NV((void *)&N_transactioninfo.outputs[i].rcm, rcm, 32);
    return zxerr_ok;

}
zxerr_t transaction_append_convert_rcv(uint8_t i, uint8_t *rcv) {
    if (i >= N_transactioninfo.n_converts) {
        return zxerr_out_of_bounds;
    }

    MEMCPY_NV((void *)&N_transactioninfo.converts[i].rcv, rcv, 32);
    return zxerr_ok;
}

void transaction_reset() {
  MEMZERO((void *)&N_transactioninfo, sizeof(transaction_info_t));
}

uint8_t transaction_get_n_spends() {
    return N_transactioninfo.n_spends;
}

uint8_t transaction_get_n_outputs() {
    return N_transactioninfo.n_outputs;
}

uint8_t transaction_get_n_converts() {
    return N_transactioninfo.n_converts;
}

uint8_t *transaction_get_spend_rcv(uint8_t i) {
    if (i >= N_transactioninfo.n_spends) {
        return NULL;
    }
    return (uint8_t*)&N_transactioninfo.spends[i].rcv;
}

uint8_t *transaction_get_spend_alpha(uint8_t i) {
    if (i >= N_transactioninfo.n_spends) {
        return NULL;
    }
    return (uint8_t*)&N_transactioninfo.spends[i].alpha;
}

uint8_t *transaction_get_output_rcv(uint8_t i) {
    if (i >= N_transactioninfo.n_outputs) {
        return NULL;
    }
    return (uint8_t*)&N_transactioninfo.outputs[i].rcv;
}

uint8_t *transaction_get_output_rcm(uint8_t i) {
    if (i >= N_transactioninfo.n_outputs) {
        return NULL;
    }
    return (uint8_t*)&N_transactioninfo.outputs[i].rcm;
}

uint8_t *transaction_get_convert_rcv(uint8_t i) {
    if (i >= N_transactioninfo.n_converts) {
        return NULL;
    }
    return (uint8_t*)&N_transactioninfo.converts[i].rcv;
}
