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


static const uint8_t hash_bond[] = {0x21, 0xc6, 0x3b, 0x00, 0xf0, 0x18, 0x63, 0x9a, 0xfa, 0xf0, 0xe3, 0x20, 0xe1, 0x68, 0x4b, 0xf0, 0x0a, 0x54, 0x01, 0x0a, 0x28, 0x2b, 0xde, 0x66, 0xcf, 0x64, 0x23, 0xcb, 0x49, 0x3d, 0x26, 0xb6};
static const uint8_t hash_unbond[] = {0xfc, 0x56, 0xa1, 0x7b, 0x2b, 0x43, 0x3d, 0x8a, 0x70, 0x2d, 0x04, 0xe2, 0xa0, 0x57, 0x73, 0x19, 0xfe, 0x54, 0x4b, 0xf8, 0x66, 0xc5, 0x98, 0x45, 0xd2, 0x83, 0x70, 0xec, 0x59, 0x31, 0xc1, 0x5e};
//static const uint8_t hash_ibc[] = {0x0f, 0x7b, 0x3e, 0x11, 0xf1, 0x3b, 0xe3, 0xef, 0x99, 0x82, 0x9d, 0x84, 0xa6, 0x75, 0xbb, 0x97, 0x13, 0x3c, 0x0f, 0x69, 0xb2, 0xcf, 0xfe, 0x8d, 0x6b, 0x02, 0x8c, 0x5a, 0x38, 0x1b, 0x46, 0x2e};
static const uint8_t hash_init_account[] = {0x2d, 0x7d, 0x19, 0xf, 0x5f, 0xc3, 0x5a, 0xf1, 0xfc, 0x1e, 0x28, 0x27, 0x4, 0x29, 0x3a, 0x27, 0x18, 0xaf, 0x38, 0x8a, 0x54, 0x72, 0x7f, 0xbf, 0xf8, 0xc9, 0xe7, 0x8d, 0xae, 0x7d, 0xe2, 0x46};
static const uint8_t hash_init_validator[] = { 0xe9, 0x50, 0x87, 0xd4, 0xcd, 0x16, 0xd6, 0xe5, 0x22, 0x75, 0x27, 0xe8, 0x15, 0xe4, 0xc6, 0x0, 0xbc, 0x66, 0x3a, 0x1a, 0xcd, 0x6d, 0x32, 0xb3, 0x3e, 0xef, 0xff, 0xc3, 0xff, 0xee, 0x3d, 0x36};
static const uint8_t hash_transfer[] = {0xc6, 0x38, 0x68, 0xb8, 0x10, 0x27, 0x13, 0x77, 0x1b, 0xf4, 0xdb, 0x94, 0x51, 0x4b, 0x89, 0x23, 0x08, 0xbd, 0xa0, 0x74, 0x4c, 0x69, 0x1f, 0x55, 0xd6, 0xcb, 0xfd, 0xa5, 0xf5, 0x69, 0x8c, 0x09};
static const uint8_t hash_update_vp[] = {0x83, 0x78, 0x7c, 0xfe, 0xc2, 0xb8, 0xf3, 0xc7, 0x32, 0x90, 0xb, 0x5b, 0xcd, 0x3a, 0x1a, 0x8a, 0x66, 0x29, 0x91, 0x5d, 0xb0, 0x64, 0xd7, 0x45, 0xc, 0xd, 0xa8, 0x1, 0x3, 0x9a, 0x86, 0xe5};
static const uint8_t hash_withdraw[] = {0x78, 0x70, 0x1e, 0xa2, 0x44, 0x1e, 0xf2, 0x7b, 0xa7, 0xbf, 0x86, 0x5a, 0xda, 0x8b, 0x7e, 0x66, 0x73, 0x9d, 0x50, 0x6d, 0xef, 0x8d, 0x93, 0x93, 0x26, 0xa0, 0x32, 0xcc, 0x0f, 0xbc, 0x54, 0xec};
// Update VP types
static const vp_types_t vp_user = {
        {0x74, 0x22, 0xae, 0x02, 0x3f, 0x42, 0x0d, 0x62, 0x91, 0x5a, 0x89, 0x24, 0x50, 0x43, 0x7e, 0xda, 0x3c, 0x60, 0x58, 0xa8, 0x64, 0x35, 0x07, 0xd9, 0x2f, 0xa0, 0x75, 0xfb, 0x11, 0xce, 0x37, 0x95},
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

    // Init validator
    if (!memcmp(codeHash.ptr, hash_init_validator, SHA256_SIZE)) {
        *type = InitValidator;
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

static parser_error_t readInitAccountTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Pubkey
    if (ctx.bufferLen != 33) {
        return parser_unexpected_value;
    }
    v->initAccount.pubkey.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.pubkey.ptr, v->initAccount.pubkey.len))

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

    ctx.offset += 32; // TODO: check this

    if ((ctx.offset != ctx.bufferLen) || (extra_data_ctx.offset != extra_data_ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}


static parser_error_t readTransferTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Source
    v->transfer.source.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.source.ptr, v->transfer.source.len))

    // Target
    v->transfer.target.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.target.ptr, v->transfer.target.len))

    // Token
    v->transfer.token.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.token.ptr, v->transfer.token.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transfer.token, &v->transfer.symbol))

    // Subprefix: read until null terminator is found
    uint8_t tmp = 0;
    CHECK_ERROR(readByte(&ctx, &tmp))

    // Amount
    CHECK_ERROR(readUint64(&ctx, &v->transfer.amount))

    ctx.offset += 2;   // Skip last 2 bytes --> Check this

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

parser_error_t readTimestamp(parser_context_t *ctx, bytes_t *timestamp) {
    if (ctx == NULL || timestamp == NULL) {
        return parser_unexpected_error;
    }
    CHECK_ERROR(readUint32(ctx, &timestamp->len))
    CHECK_ERROR(readBytes(ctx, &timestamp->ptr, timestamp->len))
    return parser_ok;
}

// WrapperTx header
parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    const uint16_t tmpOffset = ctx->offset;
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
    // Data hash
    v->transaction.header.dataHash.len = 32;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))
    // Code hash
    v->transaction.header.codeHash.len = 32;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // PoW None
    CHECK_ERROR(checkTag(ctx, 0x00))

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

parser_error_t readSections(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readUint32(ctx, &v->transaction.sections.sectionLen))

    if (v->transaction.sections.sectionLen > 6) {
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
        case Transfer:
            CHECK_ERROR(readTransferTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case InitAccount:
             CHECK_ERROR(readInitAccountTxn(&txObj->transaction.sections.data.bytes, txObj))
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
