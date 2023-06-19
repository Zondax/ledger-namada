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
#include "leb128.h"
#include "bech32.h"
#include "stdbool.h"

#define ADDRESS_LEN_BYTES   45

#define DISCRIMINANT_DATA 0x00
#define DISCRIMINANT_EXTRA_DATA 0x01
#define DISCRIMINANT_CODE 0x02
#define DISCRIMINANT_SIGNATURE 0x03
#define DISCRIMINANT_CIPHERTEXT 0x04
#define DISCRIMINANT_MASP_TX 0x05
#define DISCRIMINANT_MASP_BUILDER 0x06


static const uint8_t hash_bond[] = {0x06, 0xa9, 0x07, 0xd1, 0x83, 0x74, 0x4b, 0x4b, 0xf8, 0x26, 0xa6, 0xfa, 0xb4, 0xf3, 0x0a, 0x9e, 0x8c, 0x7, 0x84, 0xf5, 0xf8, 0x37, 0xfc, 0x78, 0x34, 0x42, 0x0d, 0x3e, 0xba, 0x7f, 0xd5, 0xc0};
static const uint8_t hash_unbond[] = {0x3f, 0xd3, 0x50, 0x60, 0x9d, 0x98, 0x86, 0x48, 0xdf, 0xac, 0x86, 0x90, 0xe4, 0x37, 0x82, 0x12, 0x12, 0xf3, 0xe9, 0x5f, 0x3f, 0x14, 0xcf, 0x78, 0x67, 0x9e, 0x10, 0xd1, 0xb3, 0x5f, 0xb5, 0xfc};
static const uint8_t hash_custom[] = {0xc2, 0x40, 0x33, 0xc0, 0xa3, 0xaf, 0x1a, 0xaf, 0x6f, 0xaa, 0x82, 0xae, 0x1, 0xae, 0x9f, 0xb4, 0x6f, 0x52, 0x41, 0xe3, 0x9b, 0xaf, 0xae, 0xff, 0xdd, 0x47, 0x18, 0x55, 0xe7, 0xaf, 0xab, 0x4a};
static const uint8_t hash_init_account[] = {0x36, 0xb6, 0xb9, 0x76, 0x92, 0xbb, 0x9d, 0xd3, 0xe8, 0xe3, 0xcc, 0x68, 0xf9, 0xe3, 0xf1, 0x9, 0x86, 0x45, 0xb3, 0xa3, 0xf4, 0x3e, 0x3e, 0x25, 0x96, 0xc9, 0x4b, 0x84, 0xcf, 0x8, 0x36, 0xa4};
#if(0)
static const uint8_t hash_init_proposal[] ={0xb5, 0x43, 0xd9, 0xba, 0x1f, 0x37, 0x00, 0xb4, 0x74, 0xe4, 0x88, 0x51, 0x44, 0x2a, 0x4e, 0xa7, 0xd5, 0xab, 0xaf, 0x2f, 0xcf, 0xb1, 0x4c, 0x2d, 0xf4, 0xad, 0xc8, 0x1b, 0x08, 0xd5, 0x44, 0x92};
#endif
static const uint8_t hash_vote_proposal[] = {0xd6, 0xf2, 0xe7, 0x29, 0xa9, 0x9f, 0xd7, 0xea, 0x1a, 0x20, 0xd7, 0x9e, 0x6f, 0x3, 0xfc, 0x98, 0x81, 0xbb, 0x1a, 0x7, 0xc, 0xac, 0xd, 0x17, 0x6d, 0xf1, 0xbf, 0x99, 0x5d, 0xd7, 0xb6, 0x23};
static const uint8_t hash_init_validator[] = {0x5f, 0xb7, 0xa6, 0xcd, 0x6f, 0x4c, 0x6e, 0x83, 0x77, 0x98, 0xc3, 0xa9, 0x99, 0x40, 0x3d, 0x76, 0x76, 0x61, 0xe6, 0x59, 0xe7, 0xc1, 0xa5, 0x64, 0x6f, 0x5c, 0x72, 0x54, 0xd2, 0x5b, 0x9f, 0xc9};
static const uint8_t hash_reveal_pubkey[] ={0x2c, 0x31, 0x46, 0xf9, 0xa8, 0x30, 0xd8, 0xa4, 0xbe, 0xbc, 0xe3, 0x1c, 0xe0, 0xf8, 0x97, 0x74, 0x36, 0x46, 0xee, 0xab, 0x84, 0xa2, 0x42, 0x1a, 0x36, 0x5d, 0xe2, 0xcc, 0xd8, 0xf1, 0x50, 0x4a};
static const uint8_t hash_transfer[] = {0xeb, 0xa, 0xde, 0x49, 0xc1, 0x3c, 0xa1, 0x2b, 0x3b, 0x82, 0x4c, 0x67, 0xc4, 0x81, 0xf8, 0x6a, 0x36, 0x53, 0x6f, 0x56, 0x88, 0x4b, 0xef, 0x66, 0x4f, 0x2b, 0x6, 0x5c, 0xec, 0xa9, 0xe1, 0xc6};
static const uint8_t hash_update_vp[] = {0xe, 0x44, 0xd6, 0x57, 0x1a, 0x4, 0xe6, 0xda, 0x2b, 0x34, 0x7a, 0xc6, 0xee, 0x49, 0xa2, 0xb9, 0x53, 0x6a, 0x6e, 0x33, 0x76, 0x3f, 0x8, 0xec, 0x2, 0x8f, 0x68, 0xaf, 0x33, 0xdc, 0x80, 0x36};
static const uint8_t hash_withdraw[] = {0x07, 0xba, 0xdb, 0xcd, 0x85, 0xfe, 0x23, 0xd4, 0xac, 0xa8, 0xa3, 0xca, 0x1e, 0xd4, 0xfc, 0x91, 0x9f, 0x72, 0xa6, 0xac, 0x81, 0x9f, 0xc2, 0xf1, 0xc1, 0xea, 0x9e, 0x68, 0xd2, 0x32, 0xf6, 0xd0};

#if(0)
// The following are strings used for reading content for init proposal
static const uint8_t proposal_abstract[] ={ 0x61, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74};
static const uint8_t proposal_authors[] = { 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x73};
static const uint8_t proposal_created[] ={ 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64};
static const uint8_t proposal_details[] = { 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73};
static const uint8_t proposal_discussions_to[] = { 0x64, 0x69, 0x73, 0x63, 0x75, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2d, 0x74, 0x6f};
static const uint8_t proposal_license[] ={ 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65};
static const uint8_t proposal_motivation[] ={ 0x6d, 0x6f, 0x74, 0x69, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e};
static const uint8_t proposal_requires[] ={ 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73};
static const uint8_t proposal_title[] ={ 0x74, 0x69, 0x74, 0x6c, 0x65};
#endif

// Update VP types
static const vp_types_t vp_user = {
        {0xea, 0x33, 0xf4, 0xff, 0x36, 0x8b, 0x85, 0x89, 0x3a, 0xb0, 0x79, 0x25, 0x69, 0x31, 0xa, 0x18, 0x39, 0x71, 0xfe, 0x99, 0x3f, 0xa8, 0x1b, 0xc3, 0x38, 0xe0, 0x36, 0x5c, 0xbc, 0xf8, 0x16, 0xad},
        "User"
};

// Add blindsigning code hash

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

    // Type is User
    if (!memcmp(vp_type_hash->ptr, vp_user.hash, SHA256_SIZE))
    {
        *vp_type_text = (char*) PIC(vp_user.text);
        return parser_ok;
    }

    return parser_unexpected_value;
}
#if(0)
parser_error_t readProposalContent(parser_context_t *ctx, parser_tx_t *v) {

    // Read the number of elements in the content
    uint32_t num_items = 0;
    CHECK_ERROR(readUint32(ctx, &num_items))

    uint32_t field_name_length = 0;
    uint8_t *field_name_ptr = NULL;

    while ( num_items > 0 ){
        // Read length of json field name
        CHECK_ERROR(readUint32(ctx, &field_name_length))

        // Read content abstract
        CHECK_ERROR(readBytes(ctx, &field_name_ptr,field_name_length ))

        // Abstract
        if (!memcmp(field_name_ptr, proposal_abstract, field_name_length)) {
            // Read length abstract
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.abstract.len))

            // Read abstract
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.abstract.ptr,v->initProposal.content.abstract.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Authors
        else if (!memcmp(field_name_ptr, proposal_authors, field_name_length)) {
            // Read length authors
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.authors.len))

            // Read authors
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.authors.ptr,v->initProposal.content.authors.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Created
        else if (!memcmp(field_name_ptr, proposal_created, field_name_length)) {
            // Read length of created
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.created.len))

            // Read created
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.created.ptr,v->initProposal.content.created.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Details
        else if (!memcmp(field_name_ptr, proposal_details, field_name_length)) {
            // Read length details
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.details.len))

            // Read details
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.details.ptr,v->initProposal.content.details.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Discussions to
        else if (!memcmp(field_name_ptr, proposal_discussions_to, field_name_length)) {
            // Read length discussions_to
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.discussions_to.len))

            // Read discussions_to
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.discussions_to.ptr,
                                  v->initProposal.content.discussions_to.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // License
        else if (!memcmp(field_name_ptr, proposal_license, field_name_length)) {
            // Read length license
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.license.len))

            // Read license
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.license.ptr,
                                  v->initProposal.content.license.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Motivation
        else if (!memcmp(field_name_ptr, proposal_motivation, field_name_length)) {
            // Read length motivation
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.motivation.len))

            // Read motivation
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.motivation.ptr,
                                  v->initProposal.content.motivation.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Require
        else if (!memcmp(field_name_ptr, proposal_requires, field_name_length)) {
            // Read length require
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.require.len))

            // Read require
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.require.ptr,
                                  v->initProposal.content.require.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        }

        // Title
        else if (!memcmp(field_name_ptr, proposal_title, field_name_length)) {
            // Read length title
            CHECK_ERROR(readUint32(ctx, &v->initProposal.content.title.len))

            // Read title
            CHECK_ERROR(readBytes(ctx, &v->initProposal.content.title.ptr,
                                  v->initProposal.content.title.len ))

            field_name_length = 0;
            field_name_ptr = NULL;
            num_items -= 1;
            continue;
        } else return parser_unexpected_value;
    }

    return parser_ok;
}
#endif

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

    uint32_t hashLen = 0;
    MEMCPY(&hashLen, pubkeyHash.ptr, sizeof(uint32_t));
    pubkeyHash.ptr += sizeof(uint32_t);
    if (hashLen != PK_HASH_LEN) {
        return parser_unexpected_value;
    }

    uint8_t tmpBuffer[FIXED_LEN_STRING_BYTES] = {0};
    snprintf((char*) tmpBuffer, sizeof(tmpBuffer), "%s", prefix);
    MEMCPY(tmpBuffer + strnlen(prefix, 5), pubkeyHash.ptr, PK_HASH_LEN);

    const char *hrp = "atest";
    const zxerr_t err = bech32EncodeFromBytes(address,
                                addressLen,
                                hrp,
                                tmpBuffer,
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

    // Bond
    if (!memcmp(codeHash.ptr, hash_bond, SHA256_SIZE)) {
        *type = Bond;
        return parser_ok;
    }
    // Unbond
    if (!memcmp(codeHash.ptr, hash_unbond, SHA256_SIZE)) {
        *type = Unbond;
        return parser_ok;
    }
    // Custom
    if (!memcmp(codeHash.ptr, hash_custom, SHA256_SIZE)) {
        *type = Custom;
        return parser_ok;
    }

    // Transfer
    if (!memcmp(codeHash.ptr, hash_transfer, SHA256_SIZE)) {
        *type = Transfer;
        return parser_ok;
    }

    // Init account
    if (!memcmp(codeHash.ptr, hash_init_account, SHA256_SIZE)) {
        *type = InitAccount;
        return parser_ok;
    }

#if(0)
    // Init proposal
    if(!memcmp(codeHash.ptr, hash_init_proposal, SHA256_SIZE)){
        *type = InitProposal;
        return parser_ok;
    }
#endif
    // Vote proposal
    if(!memcmp(codeHash.ptr, hash_vote_proposal, SHA256_SIZE)){
        *type = VoteProposal;
        return parser_ok;
    }

    // Init validator
    if (!memcmp(codeHash.ptr, hash_init_validator, SHA256_SIZE)) {
        *type = InitValidator;
        return parser_ok;
    }

    // Reveal pubkey
    if(!memcmp(codeHash.ptr, hash_reveal_pubkey, SHA256_SIZE)){
        *type = RevealPubkey;
        return parser_ok;
    }

    // Withdraw
    if (!memcmp(codeHash.ptr, hash_withdraw, SHA256_SIZE)) {
        *type = Withdraw;
        return parser_ok;
    }

    // Update VP
    if (!memcmp(codeHash.ptr,hash_update_vp,SHA256_SIZE))
    {
        *type = UpdateVP;
        return parser_ok;
    }

    *type = Unknown;
    return parser_unexpected_method;
}

static parser_error_t readInitValidatorTxn(bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
            .bufferLen = extra_data->len,
            .offset = 0,
            .tx_obj = NULL};

    v->initValidator.account_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.account_key.ptr, v->initValidator.account_key.len))

    v->initValidator.consensus_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.consensus_key.ptr, v->initValidator.consensus_key.len))

    v->initValidator.protocol_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.protocol_key.ptr, v->initValidator.protocol_key.len))

    v->initValidator.dkg_key.len = 100; //Check this size. Is fixed?
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.dkg_key.ptr, v->initValidator.dkg_key.len))

    // Commission rate
    CHECK_ERROR(readDecimal(&ctx, &v->initValidator.commission_rate));

    // Max commission rate change
    CHECK_ERROR(readDecimal(&ctx, &v->initValidator.max_commission_rate_change));

    // VP code hash
    v->initValidator.vp_type_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->initValidator.vp_type_hash.ptr, v->initValidator.vp_type_hash.len))
    // Get text from hash
    CHECK_ERROR(readVPType(&v->initValidator.vp_type_hash, &v->initValidator.vp_type_text))

    // Skip the rest of the fields
    ctx.offset = ctx.bufferLen;

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readInitAccountTxn(const bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
            .bufferLen = extra_data->len,
            .offset = 0,
            .tx_obj = NULL};
    // Pubkey
    v->initAccount.pubkey.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.pubkey.ptr, v->initAccount.pubkey.len))

    // Skip leftover bytes
    ctx.offset = ctx.bufferLen;

    // VP code hash
    v->initAccount.vp_type_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->initAccount.vp_type_hash.ptr, v->initAccount.vp_type_hash.len))
    // Get text from hash
    CHECK_ERROR(readVPType(&v->initAccount.vp_type_hash, &v->initAccount.vp_type_text))


    if ((ctx.offset != ctx.bufferLen)|| (extra_data_ctx.offset != extra_data_ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}
#if(0)
static parser_error_t readInitProposalTxn(const bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
            .bufferLen = extra_data->len,
            .offset = 0,
            .tx_obj = NULL};

    ctx.offset += 5; // TODO: check this
    // Read content
    CHECK_ERROR(readProposalContent(&ctx, v))

    v->initProposal.has_id = 0;
    if ((ctx.bufferLen - ctx.offset) > ADDRESS_LEN_BYTES + 3*sizeof(uint64_t) + 33 ){ // TODO check this, what are the last 33 bytes?
        v->initProposal.has_id = 1;
        CHECK_ERROR(readUint32(&ctx, &v->initProposal.proposal_id.len));
        CHECK_ERROR(readBytes(&ctx, &v->initProposal.proposal_id.ptr, v->initProposal.proposal_id.len))
    }

    // Author, should be of length ADDRESS_LEN_BYTES
    v->initProposal.author.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.author.ptr, v->initProposal.author.len))

    // Voting start epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_start_epoch))

    // Voting end epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_end_epoch))

    // Grace epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.grace_epoch))

    ctx.offset+=33; // TODO what are these leftover bytes?

    // Proposal code
    v->initProposal.proposal_code.len = SHA256_SIZE ;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->initProposal.proposal_code.ptr,  v->initProposal.proposal_code.len))


    if ((ctx.offset != ctx.bufferLen)|| (extra_data_ctx.offset != extra_data_ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}
#endif

static parser_error_t readVoteProposalTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Proposal ID
    CHECK_ERROR(readUint64(&ctx, &v->voteProposal.proposal_id))

    // Proposal vote
    CHECK_ERROR(readByte(&ctx, &v->voteProposal.proposal_vote))

    if (v->voteProposal.proposal_vote == Yay){
        uint8_t vote_type = 0;
        CHECK_ERROR(readByte(&ctx, &vote_type))
        switch (vote_type) {
            // Default
            case 0:
                break;

            // PGFCouncil(HashSet<Council>)
            case 1:
                {
                 uint32_t size_of_hashset = 0;
                 CHECK_ERROR(readUint32(&ctx, &size_of_hashset))
                 // A council consists of an Address (45 bytes) and an Amount (uint64)
                 uint32_t size_of_council = ADDRESS_LEN_BYTES + sizeof(uint64_t);
                 ctx.offset += size_of_hashset * size_of_council;
                 break;
                }

            // ETHBridge(Signature)
            case 2:
            {
                uint8_t signature_type = 0;
                CHECK_ERROR(readByte(&ctx, &signature_type))
                if(signature_type == 0){
                    // Ed25519 the signature consists of r (32 bytes), s (32 bytes)
                    ctx.offset += SIG_ED25519_LEN;
                }
                else if (signature_type == 1){
                    // Secp256k1 the signature consists of r [u32; 8], s [u32; 8]
                    // and the RecoveryId (1 byte)
                    ctx.offset += 65;
                } else return parser_unexpected_value;
                break;
            }
            default:
                return parser_unexpected_value;
        }
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

    ctx.offset++;  // Skip byte --> Check this

    // Source
    if (ctx.offset < ctx.bufferLen) {
        v->withdraw.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->withdraw.source.ptr, v->withdraw.source.len))
        v->withdraw.has_source = 1;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readUpdateVPTxn(const bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
                                       .bufferLen = extra_data->len,
                                       .offset = 0,
                                       .tx_obj = NULL};

    // Address
    v->updateVp.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->updateVp.address.ptr, v->updateVp.address.len))

    // VP code hash
    v->updateVp.vp_type_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->updateVp.vp_type_hash.ptr, v->updateVp.vp_type_hash.len))
    // Get text from hash
    CHECK_ERROR(readVPType(&v->updateVp.vp_type_hash, &v->updateVp.vp_type_text))

    ctx.offset += 32; // Skip tx_code_path (?)

    if ((ctx.offset != ctx.bufferLen) || (extra_data_ctx.offset != extra_data_ctx.bufferLen)) {
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

    // Subprefix, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_sub_prefix))
    if (v->transfer.has_sub_prefix){
        CHECK_ERROR(readUint32(&ctx, &v->transfer.sub_prefix.len))
        CHECK_ERROR(readBytes(&ctx, &v->transfer.sub_prefix.ptr, v->transfer.sub_prefix.len))
    }

    // Amount
    CHECK_ERROR(readUint64(&ctx, &v->transfer.amount))

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
        v->transfer.shielded_hash.len = SHA256_SIZE;
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
    MEMCPY(&v->bond.amount, ctx.buffer + ctx.offset, sizeof(uint64_t));
    ctx.offset += sizeof(uint64_t);
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

// WrapperTx header
parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
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
    v->transaction.header.codeHash.len = SHA256_SIZE;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // Data hash
    v->transaction.header.dataHash.len = SHA256_SIZE;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))

    v->transaction.header.bytes.ptr = ctx->buffer + ctx->offset;

    CHECK_ERROR(checkTag(ctx, 0x01))
    // Fee.amount
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.fees.amount))
    // Fee.address
    v->transaction.header.fees.address.len = 45;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.address.ptr, v->transaction.header.fees.address.len))
    // Pubkey
    v->transaction.header.pubkey.len = 33;   // Check first byte (0x00 | 0x01)
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.pubkey.ptr, v->transaction.header.pubkey.len))
    // Epoch
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.epoch))
    // GasLimit
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.gasLimit))

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

    return parser_ok;
}

static parser_error_t readSignature(parser_context_t *ctx, signature_section_t *signature) {
    (void) ctx;
    (void) signature;
#if 0
    if (ctx == NULL || signature == NULL) {
        return parser_unexpected_error;
    }
    // CHECK_ERROR(checkTag(ctx, 0x03))
    // CHECK_ERROR(readSalt(ctx))
    // Read hash 32 bytes
    // Read tag 0x00 -> ED25519
    // Read R 32 bytes
    // Read S 32 bytes
    // Read tag 0x00 -> ED25519
    // Read VerificationKey 32 bytes

    const uint8_t SIGNATURE_TAG = 0x03;
    const uint8_t ED25519_TAG = 0x00;

    CHECK_ERROR(checkTag(ctx, SIGNATURE_TAG))
    CHECK_ERROR(readSalt(ctx))
    signature->hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &signature->hash.ptr, signature->hash.len))

    CHECK_ERROR(checkTag(ctx, ED25519_TAG))
    signature->r.len = SIG_R_LEN;
    CHECK_ERROR(readBytes(ctx, &signature->r.ptr, signature->r.len))
    signature->s.len = SIG_S_LEN;
    CHECK_ERROR(readBytes(ctx, &signature->s.ptr, signature->s.len))

    CHECK_ERROR(checkTag(ctx, ED25519_TAG))
    signature->pubKey.len = PK_LEN_25519;
    CHECK_ERROR(readBytes(ctx, &signature->pubKey.ptr, signature->pubKey.len))
#endif
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
        return parser_unexpected_value;
    }

    for (uint32_t i = 0; i < v->transaction.sections.sectionLen; i++) {
        const uint8_t discriminant = *(ctx->buffer + ctx->offset);
        switch (discriminant) {
            case DISCRIMINANT_DATA:
                CHECK_ERROR(readDataSection(ctx, &v->transaction.sections.data))
                break;

            case DISCRIMINANT_EXTRA_DATA:
                CHECK_ERROR(readExtraDataSection(ctx, &v->transaction.sections.extraData))
                break;

            case DISCRIMINANT_CODE:
                CHECK_ERROR(readCodeSection(ctx, &v->transaction.sections.code))
                break;

            case DISCRIMINANT_SIGNATURE:
                CHECK_ERROR(readSignature(ctx, &v->transaction.sections.signatures[0]))
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
             CHECK_ERROR(readInitAccountTxn(&txObj->transaction.sections.data.bytes,&txObj->transaction.sections.extraData.bytes, txObj))
             break;
#if(0)
        case InitProposal:
            CHECK_ERROR(readInitProposalTxn(&txObj->transaction.sections.data.bytes, &txObj->transaction.sections.extraData.bytes, txObj))
            break;
#endif
        case VoteProposal:
            CHECK_ERROR(readVoteProposalTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case RevealPubkey:
            CHECK_ERROR(readRevealPubkeyTxn(&txObj->transaction.sections.data.bytes,  txObj))
            break;
        case Withdraw:
             CHECK_ERROR(readWithdrawTxn(&txObj->transaction.sections.data.bytes, txObj))
             break;
        case InitValidator:
             CHECK_ERROR(readInitValidatorTxn(&txObj->transaction.sections.data.bytes, &txObj->transaction.sections.extraData.bytes,txObj))
             break;
        case UpdateVP:
            CHECK_ERROR(readUpdateVPTxn(&txObj->transaction.sections.data.bytes, &txObj->transaction.sections.extraData.bytes, txObj))
            break;
        default:
            return parser_unexpected_method;
    }

    return  parser_ok;
}
