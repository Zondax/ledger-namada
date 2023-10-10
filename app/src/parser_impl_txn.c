/*******************************************************************************
*  (c) 2018 - 2023 Zondax AG
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
#include "parser_impl_common.h"
#include "parser_txdef.h"
#include "crypto_helper.h"
#include "leb128.h"
#include "bech32.h"
#include "stdbool.h"
#include <zxformat.h>

#define ADDRESS_LEN_BYTES   21

#define DISCRIMINANT_DATA 0x00
#define DISCRIMINANT_EXTRA_DATA 0x01
#define DISCRIMINANT_CODE 0x02
#define DISCRIMINANT_SIGNATURE 0x03
#define DISCRIMINANT_CIPHERTEXT 0x04
#define DISCRIMINANT_MASP_TX 0x05
#define DISCRIMINANT_MASP_BUILDER 0x06

static const txn_types_t allowed_txn[] = {
    {{0xa4, 0x53, 0x05, 0xb1, 0x98, 0x40, 0x05, 0x30, 0x9b, 0x77, 0xd5, 0xd7, 0x12, 0x5f, 0x15, 0x43, 0x6c, 0xc0, 0xd6, 0x39, 0x78, 0x39, 0xbc, 0x74, 0x21, 0x08, 0x77, 0x36, 0x3a, 0x97, 0x8b, 0x3c},
    Bond},

    {{0x18, 0x26, 0x82, 0xe3, 0xa0, 0xcd, 0x37, 0xa0, 0x05, 0x24, 0x2a, 0x80, 0x1c, 0x47, 0x75, 0x96, 0x19, 0x63, 0xcf, 0xd9, 0xb4, 0xe6, 0x0d, 0x03, 0xf1, 0x0a, 0x12, 0x32, 0x52, 0x58, 0x5d, 0x55},
    Unbond},

    {{0xf1, 0x35, 0x34, 0xa2, 0x1b, 0x8a, 0xfd, 0x05, 0x8e, 0x4e, 0x64, 0x36, 0x69, 0x61, 0xbd, 0x58, 0x64, 0x86, 0x49, 0x56, 0xcc, 0x91, 0x5a, 0x74, 0x5a, 0xd3, 0xcc, 0x08, 0x7e, 0xb0, 0xa6, 0xd7},
    InitAccount},

    {{0x46, 0x84, 0x4b, 0xfd, 0xbb, 0x8b, 0xfb, 0xbf, 0x44, 0xbd, 0x4e, 0xaf, 0xb7, 0xcd, 0x25, 0x46, 0x66, 0x31, 0xb2, 0xad, 0xf1, 0x9e, 0x3b, 0xa7, 0x69, 0xfe, 0x46, 0xfd, 0x52, 0xf1, 0x82, 0x57},
    InitProposal},

    {{0x3a, 0xfc, 0x69, 0x68, 0x02, 0x43, 0xb6, 0x8b, 0x2b, 0x86, 0x6b, 0xdb, 0x82, 0x7a, 0x3e, 0x90, 0x1b, 0x18, 0xaf, 0xe2, 0x7b, 0xf8, 0x5b, 0xb0, 0x40, 0x19, 0xa2, 0x6d, 0xfc, 0x1c, 0x61, 0x09},
    VoteProposal},

    {{0xbe, 0xc4, 0x86, 0xbb, 0x8c, 0xa3, 0xdd, 0xc5, 0x40, 0x19, 0xee, 0x0b, 0x8f, 0x65, 0x84, 0x9e, 0xc1, 0xf8, 0x86, 0xe5, 0x15, 0xc6, 0x5e, 0x85, 0xa0, 0x06, 0x23, 0x34, 0x12, 0xfd, 0x9a, 0xac},
    InitValidator},

    {{0x55, 0x47, 0x7e, 0x7a, 0x6c, 0x7c, 0x8d, 0x62, 0x42, 0x06, 0x39, 0x6b, 0xeb, 0x7f, 0x34, 0x06, 0x62, 0x44, 0x60, 0xb4, 0x1a, 0x78, 0x3d, 0x29, 0x9d, 0x3c, 0x3d, 0x5c, 0xcc, 0x19, 0x40, 0xc5},
    RevealPubkey},

    {{0x3f, 0x22, 0xef, 0x22, 0xdd, 0x8f, 0x1f, 0xe5, 0x1b, 0xbe, 0xf7, 0x3a, 0x97, 0x50, 0x92, 0x3b, 0x36, 0x4e, 0x3c, 0x58, 0x34, 0x9d, 0xc7, 0xe6, 0x50, 0xee, 0xcb, 0x7e, 0xa2, 0xb5, 0x75, 0x36},
    Transfer},

    {{0x7b, 0x53, 0xa6, 0xbb, 0x49, 0x9a, 0x18, 0x3e, 0xb9, 0xe4, 0x2d, 0xa2, 0xb9, 0xa7, 0xe3, 0x29, 0x63, 0x03, 0x70, 0x6f, 0x21, 0x1c, 0x79, 0x6d, 0x60, 0xd1, 0x47, 0x6b, 0xea, 0x70, 0x62, 0x50},
    UpdateVP},

    {{0xf8, 0x38, 0xcf, 0xa0, 0x72, 0x3c, 0x27, 0x48, 0x36, 0x9f, 0x70, 0x12, 0x5e, 0x13, 0x17, 0xea, 0x6a, 0x46, 0x04, 0xc1, 0xf1, 0x87, 0x18, 0x5e, 0xab, 0x23, 0x15, 0x15, 0x57, 0x38, 0x87, 0x40},
    Withdraw},

    {{0x9c, 0x06, 0x09, 0x6b, 0x65, 0x71, 0x37, 0x55, 0xe3, 0xee, 0x90, 0x49, 0x09, 0x49, 0x49, 0x7b, 0xbf, 0x99, 0xbb, 0x2a, 0x3a, 0x5b, 0x10, 0x43, 0xbc, 0xed, 0x13, 0xac, 0xc6, 0x03, 0x4c, 0xa9},
    CommissionChange},

    {{0x7d, 0x1d, 0x9c, 0x34, 0xe6, 0x9e, 0xac, 0x90, 0x69, 0xc4, 0x0d, 0x8e, 0x20, 0xa8, 0x98, 0x94, 0x62, 0x3f, 0x40, 0x62, 0x09, 0x74, 0x17, 0x40, 0x7c, 0x4d, 0xdd, 0xe3, 0x03, 0xf4, 0x0b, 0x18},
    IBC},

};
static const uint32_t allowed_txn_len = sizeof(allowed_txn) / sizeof(allowed_txn[0]);

// Update VP types
static const vp_types_t vp_user = {
        {0x1c, 0x05, 0xc8, 0x8e, 0xcb, 0x42, 0x36, 0x27, 0x53, 0xe6, 0x72, 0xdb, 0x47, 0x37, 0x70, 0xbb, 0x46, 0xb5, 0x68, 0x54, 0x49, 0xd8, 0x10, 0xcf, 0x40, 0x7b, 0xde, 0x68, 0xd9, 0x06, 0xf0, 0x8c},
        "User"
};
static const char *unknown_vp = "Unknown VP hash";

#define NAM_TOKEN(_address, _symbol) { \
        .address  = _address, \
        .symbol = _symbol, \
    }

static const tokens_t nam_tokens[] = {
    NAM_TOKEN("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5", "NAM "),
    NAM_TOKEN("atest1v4ehgw36xdzryve5gsc52veeg5cnsv2yx5eygvp38qcrvd29xy6rys6p8yc5xvp4xfpy2v694wgwcp", "BTC "),
    NAM_TOKEN("atest1v4ehgw36xqmr2d3nx3ryvd2xxgmrq33j8qcns33sxezrgv6zxdzrydjrxveygd2yxumrsdpsf9jc2p", "ETH "),
    NAM_TOKEN("atest1v4ehgw36gg6nvs2zgfpyxsfjgc65yv6pxy6nwwfsxgungdzrggeyzv35gveyxsjyxymyz335hur2jn", "DOT "),
    NAM_TOKEN("atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt", "Schnitzel "),
    NAM_TOKEN("atest1v4ehgw36gfryydj9g3p5zv3kg9znyd358ycnzsfcggc5gvecgc6ygs2rxv6ry3zpg4zrwdfeumqcz9", "Apfel "),
    NAM_TOKEN("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90", "Kartoffel "),
};

static const char* prefix_implicit = "imp::";
static const char* prefix_established = "est::";
static const char* prefix_internal = "int::";

parser_error_t readToken(const bytes_t *token, const char **symbol) {
    if (token == NULL || symbol == NULL) {
        return parser_unexpected_value;
    }

    // Convert token to address
    char address[110] = {0};
    CHECK_ERROR(readAddress(*token, address, sizeof(address)))

    const uint16_t tokenListLen = sizeof(nam_tokens) / sizeof(nam_tokens[0]);
    for (uint16_t i = 0; i < tokenListLen; i++) {
        if (!memcmp(&address, &nam_tokens[i].address, ADDRESS_LEN_TESTNET)) {
            *symbol = (char*) PIC(nam_tokens[i].symbol);
            return parser_ok;
        }
    }

    return parser_unexpected_value;
}

parser_error_t readVPType(const bytes_t *vp_type_hash, const char **vp_type_text) {
    if (vp_type_hash == NULL || vp_type_text == NULL) {
        return parser_unexpected_value;
    }

    *vp_type_text = (char*) PIC(unknown_vp);
    if (!memcmp(vp_type_hash->ptr, vp_user.hash, HASH_LEN)) {
        *vp_type_text = (char*) PIC(vp_user.text);
    }
    return parser_ok;
}

parser_error_t readAddress(bytes_t pubkeyHash, char *address, uint16_t addressLen) {
    const uint8_t addressType = *pubkeyHash.ptr++;
    const char* prefix = NULL;

    switch (addressType) {
        case 0:
            prefix = PIC(prefix_established);
            break;
        case 1:
            prefix = PIC(prefix_implicit);
            break;
        case 2:
            prefix = PIC(prefix_internal);
            break;

        default:
            return parser_value_out_of_range;
    }

    char tmpBuffer[FIXED_LEN_STRING_BYTES+1] = {0};
    snprintf(tmpBuffer, sizeof(tmpBuffer), "%s", prefix);
    const uint8_t prefixLen = strlen(prefix);
    array_to_hexstr_uppercase(tmpBuffer + prefixLen, sizeof(tmpBuffer) - prefixLen, pubkeyHash.ptr, PK_HASH_LEN);

    // Check HRP for mainnet/testnet
    const char *hrp = "atest";
    const zxerr_t err = bech32EncodeFromBytes(address,
                                addressLen,
                                hrp,
                                (uint8_t*) tmpBuffer,
                                FIXED_LEN_STRING_BYTES,
                                0,
                                BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

static parser_error_t readTransactionType(bytes_t codeHash, transaction_type_e *type) {
    if (type == NULL) {
         return parser_unexpected_error;
    }

    // Custom txn as default value
    *type = Custom;
    for (uint32_t i = 0; i < allowed_txn_len; i++) {
        if (memcmp(codeHash.ptr, allowed_txn[i].hash, HASH_LEN) == 0) {
            *type = allowed_txn[i].type;
            break;
        }
    }
    return parser_ok;
}

static parser_error_t readInitValidatorTxn(bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    v->initValidator.number_of_account_keys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->initValidator.number_of_account_keys))
    if (v->initValidator.number_of_account_keys == 0) {
        return parser_unexpected_number_items;
    }
    v->initValidator.account_keys.len = PK_LEN_25519_PLUS_TAG * v->initValidator.number_of_account_keys;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.account_keys.ptr, v->initValidator.account_keys.len))
    
    CHECK_ERROR(readByte(&ctx, &v->initValidator.threshold))

    v->initValidator.consensus_key.len = PK_LEN_25519_PLUS_TAG;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.consensus_key.ptr, v->initValidator.consensus_key.len))

    v->initValidator.eth_cold_key.len = PK_LEN_25519_PLUS_TAG;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.eth_cold_key.ptr, v->initValidator.eth_cold_key.len))

    v->initValidator.eth_hot_key.len = PK_LEN_25519_PLUS_TAG;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.eth_hot_key.ptr, v->initValidator.eth_hot_key.len))

    v->initValidator.protocol_key.len = PK_LEN_25519_PLUS_TAG;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.protocol_key.ptr, v->initValidator.protocol_key.len))

    v->initValidator.dkg_key.len = 100; //Check this size. Is fixed?
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.dkg_key.ptr, v->initValidator.dkg_key.len))

    // Commission rate
    CHECK_ERROR(readUint256(&ctx, &v->initValidator.commission_rate));

    // Max commission rate change
    CHECK_ERROR(readUint256(&ctx, &v->initValidator.max_commission_rate_change));

    // VP code hash
    v->initValidator.vp_type_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.vp_type_sechash.ptr, v->initValidator.vp_type_sechash.len))

    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        parser_context_t extra_data_ctx = {
            .buffer = extra_data[i].bytes.ptr,
            .bufferLen = extra_data[i].bytes.len,
            .offset = 0,
            .tx_obj = NULL};

        // Read the hash inside the extra data section
        bytes_t commitment = { .ptr = NULL, .len = HASH_LEN };
        CHECK_ERROR(readBytes(&extra_data_ctx, &commitment.ptr, commitment.len))

        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initValidator.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->initValidator.vp_type_secidx = extra_data[i].idx;
            v->initValidator.vp_type_hash = commitment;
            CHECK_ERROR(readVPType(&v->initValidator.vp_type_hash, &v->initValidator.vp_type_text))
            found_vp_code = true;
        }
        if (extra_data_ctx.offset != extra_data_ctx.bufferLen) {
            return parser_unexpected_characters;
        }
    }

    if (!found_vp_code) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readInitAccountTxn(const bytes_t *data,const section_t *extra_data,const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    // Pubkey
    v->initAccount.number_of_pubkeys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->initAccount.number_of_pubkeys))
    v->initAccount.pubkeys.len = 0;
    if (v->initAccount.number_of_pubkeys > 0) {
        v->initAccount.pubkeys.len = PK_LEN_25519_PLUS_TAG * v->initAccount.number_of_pubkeys;
        CHECK_ERROR(readBytes(&ctx, &v->initAccount.pubkeys.ptr, v->initAccount.pubkeys.len))
    }

    // VP code hash
    v->initAccount.vp_type_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.vp_type_sechash.ptr, v->initAccount.vp_type_sechash.len))

    // Threshold
    CHECK_ERROR(readByte(&ctx, &v->initAccount.threshold))

    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        parser_context_t extra_data_ctx = {
            .buffer = extra_data[i].bytes.ptr,
            .bufferLen = extra_data[i].bytes.len,
            .offset = 0,
            .tx_obj = NULL};

        // Read the hash inside the extra data section
        bytes_t commitment = { .ptr = NULL, .len = HASH_LEN };
        CHECK_ERROR(readBytes(&extra_data_ctx, &commitment.ptr, commitment.len))

        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initAccount.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->initAccount.vp_type_secidx = extra_data[i].idx;
            v->initAccount.vp_type_hash = commitment;
            CHECK_ERROR(readVPType(&v->initAccount.vp_type_hash, &v->initAccount.vp_type_text))
            found_vp_code = true;
        }
        if (extra_data_ctx.offset != extra_data_ctx.bufferLen) {
            return parser_unexpected_characters;
        }
    }

    if (!found_vp_code) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readPGFPaymentAction(parser_context_t *ctx, bytes_t *buf, const bool first) {
    const uint8_t tag = *(ctx->buffer + ctx->offset);
    uint32_t action_len = 1 + ADDRESS_LEN_BYTES + 32;
    switch (tag) {
        case 0: // continuous payment
            action_len += 1;
            break;
        case 1: // retro payment
            // do nothing
            break;
        default:
            return parser_unexpected_value;
    }
    
    if (first) {
        buf->len = action_len;
        CHECK_ERROR(readBytes(ctx, buf->ptr, buf->len))
    } else {
        buf->len += action_len;
        uint8_t *tmpPtr = NULL;
        CHECK_ERROR(readBytes(ctx, tmpPtr, action_len))
    }

    return parser_ok;
}

static parser_error_t readInitProposalTxn(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    MEMZERO(&v->initProposal, sizeof(v->initProposal));

    // Check if the proposal has an ID
    CHECK_ERROR(readByte(&ctx, &v->initProposal.has_id))
    if (v->initProposal.has_id){
        CHECK_ERROR(readUint64(&ctx, &v->initProposal.proposal_id));
    }

    // Read content section hash
    v->initProposal.content_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.content_sechash.ptr, v->initProposal.content_sechash.len))

    // Author, should be of length ADDRESS_LEN_BYTES
    v->initProposal.author.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.author.ptr, v->initProposal.author.len))

    // Proposal type
    v->initProposal.has_proposal_code = 0;
    CHECK_ERROR(readByte(&ctx, &v->initProposal.proposal_type))
    switch (v->initProposal.proposal_type) {
        case Default: {
            // Proposal type 0 is Default(Option<Hash>), where Hash is the proposal code.
            CHECK_ERROR(readByte(&ctx, &v->initProposal.has_proposal_code))
            if (v->initProposal.has_proposal_code) {
                v->initProposal.proposal_code_sechash.len = HASH_LEN;
                CHECK_ERROR(readBytes(&ctx, &v->initProposal.proposal_code_sechash.ptr, v->initProposal.proposal_code_sechash.len))
            }
            break;
        }

        case PGFSteward: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_steward_actions_num))
            if (v->initProposal.pgf_steward_actions_num > 0) {
                v->initProposal.pgf_steward_actions.len = (1 + ADDRESS_LEN_BYTES) * v->initProposal.pgf_steward_actions_num;
                CHECK_ERROR(readBytes(&ctx, &v->initProposal.pgf_steward_actions.ptr, v->initProposal.pgf_steward_actions.len))
            }
            break;
        }

        case PGFPayment: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_payment_actions_num))
            if (v->initProposal.pgf_payment_actions_num > 0) {
                CHECK_ERROR(readPGFPaymentAction(&ctx, &v->initProposal.pgf_payment_actions, true))
                for (uint32_t i = 1; i < v->initProposal.pgf_payment_actions_num; ++i) {
                    CHECK_ERROR(readPGFPaymentAction(&ctx, &v->initProposal.pgf_payment_actions, false))
                }
            }
            break;
        }
    
        default:
            return parser_unexpected_type;
    }

    // Voting start epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_start_epoch))

    // Voting end epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_end_epoch))

    // Grace epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.grace_epoch))

    bool found_content = false, found_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        parser_context_t extra_data_ctx = {
            .buffer = extra_data[i].bytes.ptr,
            .bufferLen = extra_data[i].bytes.len,
            .offset = 0,
            .tx_obj = NULL};

        // Read the hash inside the extra data section
        bytes_t commitment = { .ptr = NULL, .len = HASH_LEN };
        CHECK_ERROR(readBytes(&extra_data_ctx, &commitment.ptr, commitment.len))

        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initProposal.content_sechash.ptr, HASH_LEN)) {
            // If this section contains the init proposal content
            v->initProposal.content_secidx = extra_data[i].idx;
            v->initProposal.content_hash = commitment;
            found_content = true;
        }
        if (v->initProposal.has_proposal_code &&
            !memcmp(extraDataHash, v->initProposal.proposal_code_sechash.ptr, HASH_LEN))
        {
            // If this section contains the proposal code
            v->initProposal.proposal_code_secidx = extra_data[i].idx;
            v->initProposal.proposal_code_hash = commitment;
            found_code = true;
        }
        if (extra_data_ctx.offset != extra_data_ctx.bufferLen) {
            return parser_unexpected_characters;
        }
    }

    const bool code_condition = (v->initProposal.proposal_type == Default) && (v->initProposal.has_proposal_code && !found_code);
    if (!found_content || code_condition) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readVoteProposalTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Proposal ID
    CHECK_ERROR(readUint64(&ctx, &v->voteProposal.proposal_id))

    // Proposal vote
    CHECK_ERROR(readByte(&ctx, (uint8_t*) &v->voteProposal.proposal_vote))

    if (v->voteProposal.proposal_vote == Yay) {
        CHECK_ERROR(readByte(&ctx, (uint8_t*) &v->voteProposal.vote_type))
        switch (v->voteProposal.vote_type) {
            case Default:
            case PGFSteward:
            case PGFPayment:
                break;

            default:
                return parser_unexpected_value;
        }
    } else if (v->voteProposal.proposal_vote != Nay) {
        return parser_unexpected_value;
    }

    // Voter, should be of length ADDRESS_LEN_BYTES
    v->voteProposal.voter.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->voteProposal.voter.ptr, v->voteProposal.voter.len))

    // Delegators
    v->voteProposal.number_of_delegations = 0;
    CHECK_ERROR(readUint32(&ctx, &v->voteProposal.number_of_delegations))
    v->voteProposal.delegations.len = 0;
    if (v->voteProposal.number_of_delegations > 0 ){
        v->voteProposal.delegations.len = ADDRESS_LEN_BYTES*v->voteProposal.number_of_delegations;
        CHECK_ERROR(readBytes(&ctx, &v->voteProposal.delegations.ptr, v->voteProposal.delegations.len))
    }

    if ((ctx.offset != ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readRevealPubkeyTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Pubkey
    if (ctx.bufferLen != 33) {
        return parser_unexpected_value;
    }
    v->revealPubkey.pubkey.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->revealPubkey.pubkey.ptr, v->revealPubkey.pubkey.len))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readWithdrawTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->withdraw.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->withdraw.validator.ptr, v->withdraw.validator.len))

    // Does this tx specify the source
    CHECK_ERROR(readByte(&ctx, &v->withdraw.has_source))

    // Source
    if (v->withdraw.has_source != 0) {
        v->withdraw.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->withdraw.source.ptr, v->withdraw.source.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readCommissionChangeTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->commissionChange.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->commissionChange.validator.ptr, v->commissionChange.validator.len))

    // Read new commission rate
    CHECK_ERROR(readUint256(&ctx, &v->commissionChange.new_rate));


    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}


static parser_error_t readUpdateVPTxn(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Address
    v->updateVp.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->updateVp.address.ptr, v->updateVp.address.len))

    // VP code hash (optional)
    CHECK_ERROR(readByte(&ctx, &v->updateVp.has_vp_code));
    if (v->updateVp.has_vp_code == 0) {
        // Not so optional
        return parser_unexpected_value;
    }

    v->updateVp.vp_type_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->updateVp.vp_type_sechash.ptr, v->updateVp.vp_type_sechash.len))

    // Pubkeys
    v->updateVp.number_of_pubkeys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->updateVp.number_of_pubkeys))
    v->updateVp.pubkeys.len = 0;
    if (v->updateVp.number_of_pubkeys > 0) {
        v->updateVp.pubkeys.len = PK_LEN_25519_PLUS_TAG * v->updateVp.number_of_pubkeys;
        CHECK_ERROR(readBytes(&ctx, &v->updateVp.pubkeys.ptr, v->updateVp.pubkeys.len))
    }    
    
    // Threshold (optional)
    CHECK_ERROR(readByte(&ctx, &v->updateVp.has_threshold))
    if (v->updateVp.has_threshold != 0) {
        CHECK_ERROR(readByte(&ctx, &v->updateVp.threshold))
    } 
    
    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        parser_context_t extra_data_ctx = {
            .buffer = extra_data[i].bytes.ptr,
            .bufferLen = extra_data[i].bytes.len,
            .offset = 0,
            .tx_obj = NULL};

        // Read the hash inside the extra data section
        bytes_t commitment = { .ptr = NULL, .len = HASH_LEN };
        CHECK_ERROR(readBytes(&extra_data_ctx, &commitment.ptr, commitment.len))

        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->updateVp.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->updateVp.vp_type_secidx = extra_data[i].idx;
            v->updateVp.vp_type_hash = commitment;
            CHECK_ERROR(readVPType(&v->updateVp.vp_type_hash, &v->updateVp.vp_type_text))
            found_vp_code = true;
        }
        if (extra_data_ctx.offset != extra_data_ctx.bufferLen) {
            return parser_unexpected_characters;
        }
    }

    if (!found_vp_code) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readTransferTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Source
    v->transfer.source_address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.source_address.ptr, v->transfer.source_address.len))

    // Target
    v->transfer.target_address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.target_address.ptr, v->transfer.target_address.len))

    // Token
    v->transfer.token.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.token.ptr, v->transfer.token.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transfer.token, &v->transfer.symbol))

    // Amount
    CHECK_ERROR(readUint256(&ctx, &v->transfer.amount))

    // Amount denomination
    CHECK_ERROR(readByte(&ctx, &v->transfer.amount_denom))

    // Key, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_key))
    if (v->transfer.has_key){
        CHECK_ERROR(readUint32(&ctx, &v->transfer.key.len))
        // we are not displaying these bytes
        ctx.offset += v->transfer.key.len;
    }
    // shielded hash, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_shielded_hash))
    if (v->transfer.has_shielded_hash){
        v->transfer.shielded_hash.len = HASH_LEN;
        // we are not displaying these bytes
        ctx.offset += v->transfer.shielded_hash.len;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readBondUnbondTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/transaction/pos.rs#L24-L35
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->bond.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->bond.validator.ptr, v->bond.validator.len))

    // Amount
    MEMCPY(&v->bond.amount, ctx.buffer + ctx.offset, sizeof(uint256_t));
    ctx.offset += sizeof(uint256_t);
    ctx.offset++;   // Skip last byte --> Check this

    // Source
    if (ctx.offset < ctx.bufferLen) {
        v->bond.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->bond.source.ptr, v->bond.source.len))
        v->bond.has_source = 1;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readTimestamp(parser_context_t *ctx, timestamp_t *timestamp) {
    // uint64_t timestampSize = 0;
    uint8_t consumed = 0;
    uint64_t tmp = 0;

    CHECK_ERROR(checkTag(ctx, 0x38))
    const uint64_t timestampSize = ctx->bufferLen - ctx->offset;
    decodeLEB128(ctx->buffer + ctx->offset, timestampSize, &consumed, &tmp);
    ctx->offset += consumed;

    const uint32_t e9 = 1000000000;
    timestamp->millis = tmp / e9;
    timestamp->nanos = (uint32_t)(tmp - timestamp->millis*e9);

    return parser_ok;
}

static parser_error_t readIBCTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Read tag
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    // Skip URL: /ibc.applications.transfer.v1.MsgTransfer
    uint8_t tmp = 0;
    CHECK_ERROR(readByte(&ctx, &tmp))
    ctx.offset += tmp;

    CHECK_ERROR(checkTag(&ctx, 0x12))
    // Missing bytes
    CHECK_ERROR(readByte(&ctx, &tmp))
    CHECK_ERROR(readByte(&ctx, &tmp))

    // Read port id
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.port_id.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.port_id.ptr, v->ibc.port_id.len))

    // Read channel id
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.channel_id.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.channel_id.ptr, v->ibc.channel_id.len))

    // Read token address
    CHECK_ERROR(checkTag(&ctx, 0x1A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.token_address.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.token_address.ptr, v->ibc.token_address.len))

    // Read token amount
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.token_amount.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.token_amount.ptr, v->ibc.token_amount.len))

    // Read sender
    CHECK_ERROR(checkTag(&ctx, 0x22))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.sender_address.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.sender_address.ptr, v->ibc.sender_address.len))

    // Read receiver
    CHECK_ERROR(checkTag(&ctx, 0x2A))
    CHECK_ERROR(readByte(&ctx, &tmp))
    v->ibc.receiver.len = tmp;
    CHECK_ERROR(readBytes(&ctx, &v->ibc.receiver.ptr, v->ibc.receiver.len))

    // Read timeout height
    CHECK_ERROR(checkTag(&ctx, 0x32))
    CHECK_ERROR(readByte(&ctx, &v->ibc.timeout_height))

    // Read timeout timestamp
    CHECK_ERROR(readTimestamp(&ctx, &v->ibc.timeout_timestamp))

    return parser_ok;
}

// WrapperTx header
parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    v->transaction.header.bytes.ptr = ctx->buffer + ctx->offset;
    const uint16_t tmpOffset = ctx->offset;

    // Read length of chain_id
    uint32_t chain_id_len = 0;
    CHECK_ERROR(readUint32(ctx, &chain_id_len))

    ctx->offset += chain_id_len;

    // Check if an expiration is set
    uint8_t has_expiration = 0;
    CHECK_ERROR(readByte(ctx, &has_expiration))
    if (has_expiration){
        // If so, read the length of expiration, and skip it
        uint32_t expiration_len = 0;
        CHECK_ERROR(readUint32(ctx, &expiration_len))
        ctx->offset += expiration_len;
    }
    // Timestamp
    CHECK_ERROR(readUint32(ctx, &v->transaction.timestamp.len))
    CHECK_ERROR(readBytes(ctx, &v->transaction.timestamp.ptr, v->transaction.timestamp.len))

    // Code hash
    v->transaction.header.codeHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // Data hash
    v->transaction.header.dataHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))

    CHECK_ERROR(checkTag(ctx, 0x01))
    // Fee.amount
    CHECK_ERROR(readUint256(ctx, &v->transaction.header.fees.amount))

    // Fee.address
    v->transaction.header.fees.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.address.ptr, v->transaction.header.fees.address.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transaction.header.fees.address, &v->transaction.header.fees.symbol))
    // Pubkey
    v->transaction.header.pubkey.len = PK_LEN_25519_PLUS_TAG;   // Check tag (first byte: 0x00 | 0x01)
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.pubkey.ptr, v->transaction.header.pubkey.len))
    // Epoch
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.epoch))
    // GasLimit
//    CHECK_ERROR(readUint256(ctx, &v->transaction.header.gasLimit))
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.gasLimit))

    // Unshielded section hash
    uint8_t has_unshield_section_hash = 0;
    CHECK_ERROR(readByte(ctx, &has_unshield_section_hash))
    if (has_unshield_section_hash){
        v->transaction.header.unshieldSectionHash.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &v->transaction.header.unshieldSectionHash.ptr, v->transaction.header.unshieldSectionHash.len))
    }

    // Check if a PoW solution is present (should only exist in mainnet)
    uint8_t num_pow_solution = 0;
    CHECK_ERROR(readByte(ctx, &num_pow_solution))
    if (num_pow_solution){
        // A PoW solution consists of :
        // - challenge parameters = Difficulty (u8) and a Counter (u64)
        // - a SolutionValue (u64)
        // so we skip 17 bytes
        ctx->offset += num_pow_solution * 17;
    }

    v->transaction.header.bytes.len = ctx->offset - tmpOffset;

    return parser_ok;
}

static parser_error_t readSalt(parser_context_t *ctx, bytes_t *salt) {
    if (ctx == NULL || salt == NULL) {
        return parser_unexpected_error;
    }
    salt->len = SALT_LEN;
    CHECK_ERROR(readBytes(ctx, &salt->ptr, salt->len))

    return parser_ok;
}

static parser_error_t readExtraDataSection(parser_context_t *ctx, section_t *extraData) {
    if (ctx == NULL || extraData == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &extraData->discriminant))
    if (extraData->discriminant != DISCRIMINANT_EXTRA_DATA) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &extraData->salt))
    // TODO Check this byte
    uint8_t hashType = 0;
    CHECK_ERROR(readByte(ctx, &hashType))
    extraData->bytes.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &extraData->bytes.ptr, extraData->bytes.len))

    return parser_ok;
}

static parser_error_t readDataSection(parser_context_t *ctx, section_t *data) {
    if (ctx == NULL || data == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &data->discriminant))
    if (data->discriminant != DISCRIMINANT_DATA) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &data->salt))
    CHECK_ERROR(readUint32(ctx, &data->bytes.len))
    CHECK_ERROR(readBytes(ctx, &data->bytes.ptr, data->bytes.len))

    // Must make sure that header dataHash refers to this section's hash
    uint8_t dataHash[HASH_LEN] = {0};
    if (crypto_hashDataSection(data, dataHash, sizeof(dataHash)) != zxerr_ok) {
        return parser_unexpected_error;
    }
    header_t *header = &ctx->tx_obj->transaction.header;
    if (memcmp(dataHash, header->dataHash.ptr, header->dataHash.len) != 0) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

static parser_error_t readCodeSection(parser_context_t *ctx, section_t *code) {
    if (ctx == NULL || code == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &code->discriminant))
    if (code->discriminant != DISCRIMINANT_CODE) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &code->salt))
    // Check this byte
    uint8_t hashType = 0;
    CHECK_ERROR(readByte(ctx, &hashType))
    code->bytes.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &code->bytes.ptr, code->bytes.len))

    // Must make sure that header codeHash refers to this section's hash
    uint8_t codeHash[HASH_LEN] = {0};
    if (crypto_hashCodeSection(code, codeHash, sizeof(codeHash)) != zxerr_ok) {
        return parser_unexpected_error;
    }
    header_t *header = &ctx->tx_obj->transaction.header;
    if (memcmp(codeHash, header->codeHash.ptr, header->codeHash.len) != 0) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

#if(0)
static parser_error_t readCiphertext(parser_context_t *ctx, section_t *ciphertext) {
    (void) ctx;
    (void) ciphertext;
    return parser_ok;
}


static parser_error_t readMaspTx(parser_context_t *ctx, section_t *maspTx) {
    ctx->offset += 1171; // <- Transfer 2 // Transfer 1 -> 2403;//todo figure out correct number, fix this hack
    (void) maspTx;
    return parser_ok;
}

static parser_error_t readMaspBuilder(parser_context_t *ctx, section_t *maspBuilder) {
    ctx->offset += 941; // <- Transfer 2 // Transfer 1 -> 3060; //todo figure out correct number, fix this hack
    (void) maspBuilder;
    return parser_ok;
}
#endif
parser_error_t readSections(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readUint32(ctx, &v->transaction.sections.sectionLen))

    if (v->transaction.sections.sectionLen > 7) {
        return parser_invalid_output_buffer;
    }

    v->transaction.sections.extraDataLen = 0;

    for (uint32_t i = 0; i < v->transaction.sections.sectionLen; i++) {
        const uint8_t discriminant = *(ctx->buffer + ctx->offset);
        switch (discriminant) {
            case DISCRIMINANT_DATA: {
                CHECK_ERROR(readDataSection(ctx, &v->transaction.sections.data))
                v->transaction.sections.data.idx = i+1;
                break;
            }
            case DISCRIMINANT_EXTRA_DATA: {
                if (v->transaction.sections.extraDataLen >= MAX_EXTRA_DATA_SECS) {
                    return parser_unexpected_field;
                }
                section_t *extraData = &v->transaction.sections.extraData[v->transaction.sections.extraDataLen++];
                CHECK_ERROR(readExtraDataSection(ctx, extraData))
                extraData->idx = i+1;
                break;
            }
            case DISCRIMINANT_CODE: {
                CHECK_ERROR(readCodeSection(ctx, &v->transaction.sections.code))
                v->transaction.sections.code.idx = i+1;
                break;
            }
            case DISCRIMINANT_SIGNATURE:
                break;
#if(0)
            case DISCRIMINANT_CIPHERTEXT:
                CHECK_ERROR(readCiphertext(ctx, &v->transaction.sections.ciphertext))
                break;

            case DISCRIMINANT_MASP_TX:
                CHECK_ERROR(readMaspTx(ctx, &v->transaction.sections.maspTx))
                break;

            case DISCRIMINANT_MASP_BUILDER:
                CHECK_ERROR(readMaspBuilder(ctx, &v->transaction.sections.maspBuilder))
                break;
#endif
            default:
                return parser_unexpected_field;
        }
    }

    return parser_ok;
}

parser_error_t validateTransactionParams(parser_tx_t *txObj) {
    if (txObj == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readTransactionType(txObj->transaction.sections.code.bytes, &txObj->typeTx))
    switch (txObj->typeTx) {
        case Bond:
        case Unbond:
            CHECK_ERROR(readBondUnbondTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case Custom:
            break;
        case Transfer:
            CHECK_ERROR(readTransferTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case InitAccount:
            CHECK_ERROR(readInitAccountTxn(&txObj->transaction.sections.data.bytes,txObj->transaction.sections.extraData,txObj->transaction.sections.extraDataLen,txObj))
            break;
        case InitProposal:
            CHECK_ERROR(readInitProposalTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case VoteProposal:
            CHECK_ERROR(readVoteProposalTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case RevealPubkey:
            CHECK_ERROR(readRevealPubkeyTxn(&txObj->transaction.sections.data.bytes,  txObj))
            break;
        case Withdraw:
            CHECK_ERROR(readWithdrawTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case CommissionChange:
            CHECK_ERROR(readCommissionChangeTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case InitValidator:
            CHECK_ERROR(readInitValidatorTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UpdateVP:
            CHECK_ERROR(readUpdateVPTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case IBC:
            CHECK_ERROR(readIBCTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        default:
            return parser_unexpected_method;
    }

    return  parser_ok;
}
