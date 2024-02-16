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
#include "allowed_transactions.h"
#include "txn_validator.h"
#include "txn_delegation.h"
#include "stdbool.h"
#include <zxformat.h>
#include "mem.c"

#define DISCRIMINANT_DATA 0x00
#define DISCRIMINANT_EXTRA_DATA 0x01
#define DISCRIMINANT_CODE 0x02
#define DISCRIMINANT_SIGNATURE 0x03
#define DISCRIMINANT_CIPHERTEXT 0x04
#define DISCRIMINANT_MASP_TX 0x05
#define DISCRIMINANT_MASP_BUILDER 0x06

// Update VP types
static const vp_types_t vp_user = { "vp_user.wasm", "User"};
static const vp_types_t vp_validator = { "vp_validator.wasm", "Validator"};

#define NAM_TOKEN(_address, _symbol) { \
        .address  = _address, \
        .symbol = _symbol, \
    }

static const tokens_t nam_tokens[] = {
    NAM_TOKEN("tnam1qye0m4890at9r92pfyf3948fpzgryfzweg2v95fs", "NAM "),
    NAM_TOKEN("tnam1qx3jyxy292rlqu40syq3nfnlgtsusyewkcuyddhp", "BTC "),
    NAM_TOKEN("tnam1q8dug9yu52tzz3mmn976574fj7yfl4yj0qynxvrk", "ETH "),
    NAM_TOKEN("tnam1q8d2xskmexg9j9yvfda7cwy48vy8wrmwsuw5lxtv", "DOT "),
    NAM_TOKEN("tnam1q8qy9puaq5plu2csa4gk3l2fpl5vc4r2ccxqjhqk", "Schnitzel "),
    NAM_TOKEN("tnam1q9zsxkpuk4sle4lhfcfnu5fdep8fy3n2aqufyc97", "Apfel "),
    NAM_TOKEN("tnam1qyev25082t47tqxmj4gd4c07d3pm9t6rnc7jgwyq", "Kartoffel "),
};

#define PREFIX_IMPLICIT 0
#define PREFIX_ESTABLISHED 1
#define PREFIX_INTERNAL 2

parser_error_t readUint128(parser_context_t *ctx, uint128_t *value) {
    if (value == NULL || ctx->offset + sizeof(uint128_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(uint128_t));
    ctx->offset += sizeof(uint128_t);
    return parser_ok;
}

parser_error_t readInt128(parser_context_t *ctx, int128_t *value) {
    if (value == NULL || ctx->offset + sizeof(int128_t) > ctx->bufferLen) {
        return parser_unexpected_error;
    }

    MEMCPY(value, ctx->buffer + ctx->offset, sizeof(int128_t));
    ctx->offset += sizeof(int128_t);
    return parser_ok;
}

parser_error_t readBytesAlt(parser_context_t *ctx, uint8_t *output, uint16_t outputLen) {
    if (ctx->offset + outputLen > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    MEMCPY(output, ctx->buffer + ctx->offset, outputLen);
    ctx->offset += outputLen;
    return parser_ok;
}

parser_error_t readAssetType_i128(parser_context_t *ctx, AssetType_i128 *obj);
parser_error_t readAssetType(parser_context_t *ctx, AssetType *obj);
parser_error_t readAuthorized(parser_context_t *ctx, Authorized *obj);
parser_error_t readBlockHeight(parser_context_t *ctx, BlockHeight *obj);
parser_error_t readBranchId(parser_context_t *ctx, BranchId *obj);
parser_error_t readConvertDescriptionV5(parser_context_t *ctx, ConvertDescriptionV5 *obj);
parser_error_t readEphemeralKeyBytes(parser_context_t *ctx, EphemeralKeyBytes *obj);
parser_error_t readNullifier(parser_context_t *ctx, Nullifier *obj);
parser_error_t readOutputDescriptionV5(parser_context_t *ctx, OutputDescriptionV5 *obj);
parser_error_t readPublicKey(parser_context_t *ctx, PublicKey *obj);
parser_error_t readSignature(parser_context_t *ctx, Signature *obj);
parser_error_t readSpendDescriptionV5(parser_context_t *ctx, SpendDescriptionV5 *obj);
parser_error_t readTransaction(parser_context_t *ctx, Transaction *obj);
parser_error_t readCompactSize(parser_context_t *ctx, CompactSize *obj);
parser_error_t readTransaction_authorization(parser_context_t *ctx, Transaction_authorization *obj, uint64_t sd_v5s_count, uint64_t cd_v5s_count, uint64_t od_v5s_count);
parser_error_t readTransaction_convert_anchor(parser_context_t *ctx, Transaction_convert_anchor *obj, uint64_t cd_v5s_count);
parser_error_t readTransaction_spend_anchor(parser_context_t *ctx, Transaction_spend_anchor *obj, uint64_t sd_v5s_count);
parser_error_t readTransaction_value_balance(parser_context_t *ctx, Transaction_value_balance *obj, uint64_t sd_v5s_count, uint64_t cd_v5s_count, uint64_t od_v5s_count);
parser_error_t readTransparentAddress(parser_context_t *ctx, TransparentAddress *obj);
parser_error_t readTxInAuthorized(parser_context_t *ctx, TxInAuthorized *obj);
parser_error_t readTxOut(parser_context_t *ctx, TxOut *obj);
parser_error_t readTxVersion(parser_context_t *ctx, TxVersion *obj);
parser_error_t readValueSumAssetType_i128(parser_context_t *ctx, ValueSumAssetType_i128 *obj);


parser_error_t readAssetType_i128(parser_context_t *ctx, AssetType_i128 *obj) {
  CHECK_ERROR(readAssetType(ctx, &obj->f0))
  CHECK_ERROR(readInt128(ctx, &obj->f1))
  return parser_ok;
}

parser_error_t readAssetType(parser_context_t *ctx, AssetType *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->identifier, 32))
  return parser_ok;
}

parser_error_t readAuthorized(parser_context_t *ctx, Authorized *obj) {
  CHECK_ERROR(readSignature(ctx, &obj->binding_sig))
  return parser_ok;
}

parser_error_t readBlockHeight(parser_context_t *ctx, BlockHeight *obj) {
  CHECK_ERROR(readUint32(ctx, &obj->f0))
  return parser_ok;
}

parser_error_t readBranchId(parser_context_t *ctx, BranchId *obj) {
  CHECK_ERROR(readUint32(ctx, &obj->tag))
  switch(obj->tag) {
  }
  return parser_ok;
}

parser_error_t readConvertDescriptionV5(parser_context_t *ctx, ConvertDescriptionV5 *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->cv, 32))
  return parser_ok;
}

parser_error_t readEphemeralKeyBytes(parser_context_t *ctx, EphemeralKeyBytes *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->f0, 32))
  return parser_ok;
}

parser_error_t readNullifier(parser_context_t *ctx, Nullifier *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->f0, 32))
  return parser_ok;
}

parser_error_t readOutputDescriptionV5(parser_context_t *ctx, OutputDescriptionV5 *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->cv, 32))
  CHECK_ERROR(readBytesAlt(ctx, obj->cmu, 32))
  CHECK_ERROR(readEphemeralKeyBytes(ctx, &obj->ephemeral_key))
  CHECK_ERROR(readBytesAlt(ctx, obj->enc_ciphertext, 612))
  CHECK_ERROR(readBytesAlt(ctx, obj->out_ciphertext, 80))
  return parser_ok;
}

parser_error_t readPublicKey(parser_context_t *ctx, PublicKey *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->f0, 32))
  return parser_ok;
}

parser_error_t readSignature(parser_context_t *ctx, Signature *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->rbar, 32))
  CHECK_ERROR(readBytesAlt(ctx, obj->sbar, 32))
  return parser_ok;
}

parser_error_t readSpendDescriptionV5(parser_context_t *ctx, SpendDescriptionV5 *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->cv, 32))
  CHECK_ERROR(readNullifier(ctx, &obj->nullifier))
  CHECK_ERROR(readPublicKey(ctx, &obj->rk))
  return parser_ok;
}

uint64_t decompactSize(CompactSize *obj) {
  switch(obj->tag) {
  case 253:
  return obj->u16;
  case 254:
  return obj->u32;
  case 255:
  return obj->u64;
  default:
  return obj->tag;
  }
}

parser_error_t readTransaction(parser_context_t *ctx, Transaction *obj) {
  CHECK_ERROR(readTxVersion(ctx, &obj->version))
  CHECK_ERROR(readBranchId(ctx, &obj->consensus_branch_id))
  CHECK_ERROR(readUint32(ctx, &obj->lock_time))
  CHECK_ERROR(readBlockHeight(ctx, &obj->expiry_height))
  CHECK_ERROR(readCompactSize(ctx, &obj->vin_count))
    uint64_t vin_count = decompactSize(&obj->vin_count);
  if((obj->vin = mem_alloc(vin_count * sizeof(TxInAuthorized))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < vin_count; i++) {
    CHECK_ERROR(readTxInAuthorized(ctx, &obj->vin[i]))
  }
  CHECK_ERROR(readCompactSize(ctx, &obj->vout_count))
  uint64_t vout_count = decompactSize(&obj->vout_count);
  if((obj->vout = mem_alloc(vout_count * sizeof(TxOut))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < vout_count; i++) {
    CHECK_ERROR(readTxOut(ctx, &obj->vout[i]))
  }
  CHECK_ERROR(readCompactSize(ctx, &obj->sd_v5s_count))
  uint64_t sd_v5s_count = decompactSize(&obj->sd_v5s_count);
  if((obj->sd_v5s = mem_alloc(sd_v5s_count * sizeof(SpendDescriptionV5))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < sd_v5s_count; i++) {
    CHECK_ERROR(readSpendDescriptionV5(ctx, &obj->sd_v5s[i]))
  }
  CHECK_ERROR(readCompactSize(ctx, &obj->cd_v5s_count))
  uint64_t cd_v5s_count = decompactSize(&obj->cd_v5s_count);
  if((obj->cd_v5s = mem_alloc(cd_v5s_count * sizeof(ConvertDescriptionV5))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < cd_v5s_count; i++) {
    CHECK_ERROR(readConvertDescriptionV5(ctx, &obj->cd_v5s[i]))
  }
  CHECK_ERROR(readCompactSize(ctx, &obj->od_v5s_count))
  uint64_t od_v5s_count = decompactSize(&obj->od_v5s_count);
  if((obj->od_v5s = mem_alloc(od_v5s_count * sizeof(OutputDescriptionV5))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < od_v5s_count; i++) {
    CHECK_ERROR(readOutputDescriptionV5(ctx, &obj->od_v5s[i]))
      }
  CHECK_ERROR(readTransaction_value_balance(ctx, &obj->value_balance, sd_v5s_count, cd_v5s_count, od_v5s_count))
    CHECK_ERROR(readTransaction_spend_anchor(ctx, &obj->spend_anchor, sd_v5s_count))
    CHECK_ERROR(readTransaction_convert_anchor(ctx, &obj->convert_anchor, cd_v5s_count))
  if((obj->v_spend_proofs = mem_alloc(sd_v5s_count * sizeof(uint8_t[192]))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < sd_v5s_count; i++) {
    CHECK_ERROR(readBytesAlt(ctx, obj->v_spend_proofs[i], 192))
  }
  if((obj->v_spend_auth_sigs = mem_alloc(sd_v5s_count * sizeof(Signature))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < sd_v5s_count; i++) {
    CHECK_ERROR(readSignature(ctx, &obj->v_spend_auth_sigs[i]))
  }
  if((obj->v_convert_proofs = mem_alloc(cd_v5s_count * sizeof(uint8_t[192]))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < cd_v5s_count; i++) {
    CHECK_ERROR(readBytesAlt(ctx, obj->v_convert_proofs[i], 192))
  }
  if((obj->v_output_proofs = mem_alloc(od_v5s_count * sizeof(uint8_t[192]))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < od_v5s_count; i++) {
    CHECK_ERROR(readBytesAlt(ctx, obj->v_output_proofs[i], 192))
  }
  CHECK_ERROR(readTransaction_authorization(ctx, &obj->authorization, sd_v5s_count, cd_v5s_count, od_v5s_count))
  return parser_ok;
}

parser_error_t readCompactSize(parser_context_t *ctx, CompactSize *obj) {
  CHECK_ERROR(readByte(ctx, &obj->tag))
  switch(obj->tag) {
  case 253:
  CHECK_ERROR(readUint16(ctx, &obj->u16))
  break;
  case 254:
  CHECK_ERROR(readUint32(ctx, &obj->u32))
  break;
  case 255:
  CHECK_ERROR(readUint64(ctx, &obj->u64))
  break;
  }
  return parser_ok;
}

parser_error_t readTransaction_authorization(parser_context_t *ctx, Transaction_authorization *obj, uint64_t sd_v5s_count, uint64_t cd_v5s_count, uint64_t od_v5s_count) {
  switch(sd_v5s_count > 0 || cd_v5s_count > 0 || od_v5s_count > 0) {
  case 0:
  break;
  case 1:
  CHECK_ERROR(readAuthorized(ctx, &obj->Some))
  break;
  }
  return parser_ok;
}

parser_error_t readTransaction_convert_anchor(parser_context_t *ctx, Transaction_convert_anchor *obj, uint64_t cd_v5s_count) {
  switch(cd_v5s_count > 0) {
  case 0:
  break;
  case 1:
  CHECK_ERROR(readBytesAlt(ctx, obj->Some, 32))
  break;
  }
  return parser_ok;
}

parser_error_t readTransaction_spend_anchor(parser_context_t *ctx, Transaction_spend_anchor *obj, uint64_t sd_v5s_count) {
  switch(sd_v5s_count > 0) {
  case 0:
  break;
  case 1:
  CHECK_ERROR(readBytesAlt(ctx, obj->Some, 32))
  break;
  }
  return parser_ok;
}

parser_error_t readTransaction_value_balance(parser_context_t *ctx, Transaction_value_balance *obj, uint64_t sd_v5s_count, uint64_t cd_v5s_count, uint64_t od_v5s_count) {
  switch(sd_v5s_count > 0 || cd_v5s_count > 0 || od_v5s_count > 0) {
  case 0:
  break;
  case 1:
  CHECK_ERROR(readValueSumAssetType_i128(ctx, &obj->Some))
  break;
  }
  return parser_ok;
}

parser_error_t readTransparentAddress(parser_context_t *ctx, TransparentAddress *obj) {
  CHECK_ERROR(readBytesAlt(ctx, obj->f0, 20))
  return parser_ok;
}

parser_error_t readTxInAuthorized(parser_context_t *ctx, TxInAuthorized *obj) {
  CHECK_ERROR(readAssetType(ctx, &obj->asset_type))
  CHECK_ERROR(readUint64(ctx, &obj->value))
  CHECK_ERROR(readTransparentAddress(ctx, &obj->address))
  return parser_ok;
}

parser_error_t readTxOut(parser_context_t *ctx, TxOut *obj) {
  CHECK_ERROR(readAssetType(ctx, &obj->asset_type))
  CHECK_ERROR(readUint64(ctx, &obj->value))
  CHECK_ERROR(readTransparentAddress(ctx, &obj->address))
  return parser_ok;
}

parser_error_t readTxVersion(parser_context_t *ctx, TxVersion *obj) {
  CHECK_ERROR(readUint32(ctx, &obj->header))
  CHECK_ERROR(readUint32(ctx, &obj->version_group_id))
  return parser_ok;
}

parser_error_t readValueSumAssetType_i128(parser_context_t *ctx, ValueSumAssetType_i128 *obj) {
  CHECK_ERROR(readCompactSize(ctx, &obj->f0))
  uint64_t f0 = decompactSize(&obj->f0);
  if((obj->f1 = mem_alloc(f0 * sizeof(AssetType_i128))) == NULL) {
    return parser_unexpected_error;
  }
  for(uint32_t i = 0; i < f0; i++) {
    CHECK_ERROR(readAssetType_i128(ctx, &obj->f1[i]))
  }
  return parser_ok;
}








parser_error_t readToken(const bytes_t *token, const char **symbol) {
    if (token == NULL || symbol == NULL) {
        return parser_unexpected_value;
    }

    // Convert token to address
    char address[53] = {0};
    CHECK_ERROR(readAddress(*token, address, sizeof(address)))

    *symbol = NULL;

    const uint16_t tokenListLen = sizeof(nam_tokens) / sizeof(nam_tokens[0]);
    for (uint16_t i = 0; i < tokenListLen; i++) {
        if (!memcmp(&address, &nam_tokens[i].address, ADDRESS_LEN_TESTNET)) {
            *symbol = (char*) PIC(nam_tokens[i].symbol);
            return parser_ok;
        }
    }

    return parser_ok;
}

parser_error_t readVPType(const bytes_t *vp_type_tag, const char **vp_type_text) {
    if (vp_type_tag == NULL || vp_type_text == NULL) {
        return parser_unexpected_value;
    }

    *vp_type_text = NULL;
    if (vp_type_tag->ptr == NULL) {
        return parser_ok;
    }

    if (strnlen(vp_user.tag, sizeof(vp_user.tag)) == vp_type_tag->len &&
        !memcmp(vp_type_tag->ptr, vp_user.tag, vp_type_tag->len)) {
        *vp_type_text = (char*) PIC(vp_user.text);
    } else if (strnlen(vp_validator.tag, sizeof(vp_validator.tag)) == vp_type_tag->len &&
               memcmp(vp_type_tag->ptr, vp_validator.tag, vp_type_tag->len) == 0) {
        *vp_type_text = (char*) PIC(vp_validator.text);
    }

    return parser_ok;
}

parser_error_t readAddress(bytes_t pubkeyHash, char *address, uint16_t addressLen) {
    const uint8_t addressType = *pubkeyHash.ptr++;
    uint8_t tmpBuffer[ADDRESS_LEN_BYTES] = {0};

    switch (addressType) {
        case 0:
            tmpBuffer[0] = PREFIX_ESTABLISHED;
            break;
        case 1:
            tmpBuffer[1] = PREFIX_IMPLICIT;
            break;
        case 2:
            tmpBuffer[2] = PREFIX_INTERNAL;
            break;

        default:
            return parser_value_out_of_range;
    }

    MEMCPY(tmpBuffer + 1, pubkeyHash.ptr, 20);

    // Check HRP for mainnet/testnet
    const char *hrp = "tnam";
    const zxerr_t err = bech32EncodeFromBytes(address,
                                addressLen,
                                hrp,
                                (uint8_t*) tmpBuffer,
                                ADDRESS_LEN_BYTES,
                                1,
                                BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

static parser_error_t readTransactionType(bytes_t *codeTag, transaction_type_e *type) {
    if (codeTag == NULL || type == NULL) {
         return parser_unexpected_error;
    }

    // Custom txn as default value
    *type = Custom;
    if (codeTag->ptr == NULL) {
        return parser_ok;
    }

    for (uint32_t i = 0; i < allowed_txn_len; i++) {
        if (strnlen(allowed_txn[i].tag, sizeof(allowed_txn[i].tag)) == codeTag->len &&
            memcmp(codeTag->ptr, allowed_txn[i].tag, codeTag->len) == 0) {
            *type = allowed_txn[i].type;
            break;
        }
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
    v->initAccount.pubkeys.ptr = ctx.buffer + ctx.offset;
    v->initAccount.pubkeys.len = 0;
    bytes_t tmpPubkey = {0};
    for (uint32_t i = 0; i < v->initAccount.number_of_pubkeys; i++) {
        CHECK_ERROR(readPubkey(&ctx, &tmpPubkey))
        v->initAccount.pubkeys.len += tmpPubkey.len;
    }

    // VP code hash
    v->initAccount.vp_type_sechash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.vp_type_sechash.ptr, v->initAccount.vp_type_sechash.len))

    // Threshold
    CHECK_ERROR(readByte(&ctx, &v->initAccount.threshold))

    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen; i++) {
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initAccount.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->initAccount.vp_type_secidx = extra_data[i].idx;
            v->initAccount.vp_type_hash.ptr = extra_data[i].bytes_hash;
            v->initAccount.vp_type_hash.len = HASH_LEN;
            CHECK_ERROR(readVPType(&extra_data[i].tag, &v->initAccount.vp_type_text))
            found_vp_code = true;
        }
    }

    if (!found_vp_code) {
        return parser_missing_field;
    } else if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
static parser_error_t readPGFInternal(parser_context_t *ctx, pgf_payment_action_t *paymentAction) {
    if (ctx == NULL || paymentAction == NULL) {
        return parser_unexpected_error;
    }

    // Read target
    paymentAction->internal.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(ctx, &paymentAction->internal.address.ptr, paymentAction->internal.address.len))
    // Read amount
    paymentAction->internal.amount.len = 32;
    CHECK_ERROR(readBytes(ctx, &paymentAction->internal.amount.ptr, paymentAction->internal.amount.len))

    return parser_ok;
}

static parser_error_t readPGFTargetIBC(parser_context_t *ctx, pgf_payment_action_t *paymentAction) {
    if (ctx == NULL || paymentAction == NULL) {
        return parser_unexpected_error;
    }

    // Read target
    uint32_t tmpValue = 0;
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    paymentAction->ibc.target.len = tmpValue;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.target.ptr, paymentAction->ibc.target.len))

    // Read token amount
    paymentAction->ibc.amount.len = 32;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.amount.ptr, paymentAction->ibc.amount.len))

    // Read port id
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    paymentAction->ibc.portId.len = tmpValue;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.portId.ptr, paymentAction->ibc.portId.len))

    // Read channel id
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    paymentAction->ibc.channelId.len = tmpValue;
    CHECK_ERROR(readBytes(ctx, &paymentAction->ibc.channelId.ptr, paymentAction->ibc.channelId.len))

    return parser_ok;
}

parser_error_t readPGFPaymentAction(parser_context_t *ctx, pgf_payment_action_t *paymentAction) {
    if (ctx == NULL || paymentAction == NULL || ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_error;
    }

    const uint16_t startOffset = ctx->offset;

    CHECK_ERROR(readByte(ctx, (uint8_t*) &paymentAction->action));

    if (paymentAction->action > Retro) {
        return parser_value_out_of_range;
    }

    if (paymentAction->action == Continuous) {
        CHECK_ERROR(readByte(ctx, (uint8_t*) &paymentAction->add_rem));
    }

    CHECK_ERROR(readByte(ctx, (uint8_t*) &paymentAction->targetType));
    switch (paymentAction->targetType) {
        case PGFTargetInternal:
            CHECK_ERROR(readPGFInternal(ctx, paymentAction))
            break;

        case PGFTargetIBC:
            CHECK_ERROR(readPGFTargetIBC(ctx, paymentAction))
            break;

        default:
            return parser_unexpected_error;
    }

    paymentAction->length = ctx->offset - startOffset;
    return parser_ok;
}

static parser_error_t readInitProposalTxn(const bytes_t *data, const section_t *extra_data, const uint32_t extraDataLen, parser_tx_t *v) {
    if (data == NULL || extra_data == NULL || v == NULL || extraDataLen >= MAX_EXTRA_DATA_SECS) {
        return parser_unexpected_value;
    }
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    MEMZERO(&v->initProposal, sizeof(v->initProposal));

    // Check if the proposal has an ID
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.proposal_id));

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
            v->initProposal.pgf_steward_actions.ptr = ctx.buffer + ctx.offset;
            v->initProposal.pgf_steward_actions.len = 0;

            uint8_t add_rem_discriminant = 0;
            bytes_t tmpBytes = {.ptr = NULL, .len = ADDRESS_LEN_BYTES};
            for (uint32_t i = 0; i < v->initProposal.pgf_steward_actions_num; i++) {
                CHECK_ERROR(readByte(&ctx, &add_rem_discriminant))
                CHECK_ERROR(readBytes(&ctx, &tmpBytes.ptr, tmpBytes.len))
                v->initProposal.pgf_steward_actions.len += 1 + ADDRESS_LEN_BYTES;
            }
            break;
        }

        case PGFPayment: {
            CHECK_ERROR(readUint32(&ctx, &v->initProposal.pgf_payment_actions_num))
            if (v->initProposal.pgf_payment_actions_num > 0) {
                v->initProposal.pgf_payment_actions.ptr = ctx.buffer + ctx.offset;
                v->initProposal.pgf_payment_actions.len = 0;
                v->initProposal.pgf_payment_ibc_num = 0;
                pgf_payment_action_t tmpPGFPayment = {0};
                for (uint32_t i = 0; i < v->initProposal.pgf_payment_actions_num; i++) {
                    CHECK_ERROR(readPGFPaymentAction(&ctx, &tmpPGFPayment))
                    v->initProposal.pgf_payment_actions.len += tmpPGFPayment.length;
                    if (tmpPGFPayment.targetType == PGFTargetIBC) {
                        v->initProposal.pgf_payment_ibc_num++;
                    }
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
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->initProposal.content_sechash.ptr, HASH_LEN)) {
            // If this section contains the init proposal content
            v->initProposal.content_secidx = extra_data[i].idx;
            // MEMCPY(v->initProposal.content_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            v->initProposal.content_hash.ptr = extra_data[i].bytes_hash;
            v->initProposal.content_hash.len = HASH_LEN;
            found_content = true;
        }
        if (v->initProposal.proposal_type == Default && v->initProposal.has_proposal_code &&
            !memcmp(extraDataHash, v->initProposal.proposal_code_sechash.ptr, HASH_LEN)) {
            // If this section contains the proposal code
            v->initProposal.proposal_code_secidx = extra_data[i].idx;
            v->initProposal.proposal_code_hash.ptr = extra_data[i].bytes_hash;
            v->initProposal.proposal_code_hash.len = HASH_LEN;
            // MEMCPY(v->initProposal.proposal_code_hash, extra_data[i].bytes_hash, CX_SHA256_SIZE);
            found_code = true;
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

    if (v->voteProposal.proposal_vote > Abstain) {
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
    CHECK_ERROR(readPubkey(&ctx, &v->revealPubkey.pubkey))

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
    v->commissionChange.new_rate.len = 32;
    CHECK_ERROR(readBytes(&ctx, &v->commissionChange.new_rate.ptr, v->commissionChange.new_rate.len))


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
    if (v->updateVp.has_vp_code) {
        v->updateVp.vp_type_sechash.len = HASH_LEN;
        CHECK_ERROR(readBytes(&ctx, &v->updateVp.vp_type_sechash.ptr, v->updateVp.vp_type_sechash.len))
    }

    // Pubkeys
    v->updateVp.number_of_pubkeys = 0;
    CHECK_ERROR(readUint32(&ctx, &v->updateVp.number_of_pubkeys))
    v->updateVp.pubkeys.len = 0;
    v->updateVp.pubkeys.ptr = ctx.buffer + ctx.offset;
    for (uint32_t i = 0; i < v->updateVp.number_of_pubkeys; i++) {
        bytes_t tmpPubkey = {0};
        CHECK_ERROR(readPubkey(&ctx, &tmpPubkey))
        v->updateVp.pubkeys.len += tmpPubkey.len;
    }

    // Threshold (optional)
    CHECK_ERROR(readByte(&ctx, &v->updateVp.has_threshold))
    if (v->updateVp.has_threshold != 0) {
        CHECK_ERROR(readByte(&ctx, &v->updateVp.threshold))
    }

    bool found_vp_code = false;
    // Load the linked to data from the extra data sections
    for (uint32_t i = 0; i < extraDataLen * v->updateVp.has_vp_code; i++) {
        uint8_t extraDataHash[HASH_LEN] = {0};
        if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
            return parser_unexpected_error;
        }

        if (!memcmp(extraDataHash, v->updateVp.vp_type_sechash.ptr, HASH_LEN)) {
            // If this section contains the VP code hash
            v->updateVp.vp_type_secidx = extra_data[i].idx;
            v->updateVp.vp_type_hash.ptr = extra_data[i].bytes_hash;
            v->updateVp.vp_type_hash.len = HASH_LEN;
            CHECK_ERROR(readVPType(&extra_data[i].tag, &v->updateVp.vp_type_text))
            found_vp_code = true;
        }
    }

    if (v->updateVp.has_vp_code && !found_vp_code) {
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
    v->transfer.amount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.amount.ptr, v->transfer.amount.len))

    // Amount denomination
    CHECK_ERROR(readByte(&ctx, &v->transfer.amount_denom))

    uint32_t tmpValue = 0;
    // Key, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_key))
    if (v->transfer.has_key){
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        v->transfer.key.len = (uint16_t)tmpValue;
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

static parser_error_t readResignSteward(const bytes_t *data, tx_resign_steward_t *resignSteward) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    resignSteward->steward.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &resignSteward->steward.ptr, resignSteward->steward.len))
    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readChangeConsensusKey(const bytes_t *data, tx_consensus_key_change_t *consensusKeyChange) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    consensusKeyChange->validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &consensusKeyChange->validator.ptr, consensusKeyChange->validator.len))
    // Consensus key
    CHECK_ERROR(readPubkey(&ctx, &consensusKeyChange->consensus_key))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readUpdateStewardCommission(const bytes_t *data, tx_update_steward_commission_t *updateStewardCommission) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Address
    updateStewardCommission->steward.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &updateStewardCommission->steward.ptr, updateStewardCommission->steward.len))

    updateStewardCommission->commissionLen = 0;
    CHECK_ERROR(readUint32(&ctx, &updateStewardCommission->commissionLen))

    updateStewardCommission->commission.ptr = ctx.buffer + ctx.offset;
    const uint16_t startOffset = ctx.offset;
    bytes_t address = {.ptr = NULL, .len = ADDRESS_LEN_BYTES};
    bytes_t amount = {.ptr = NULL, .len = 32};
    for (uint32_t i = 0; i < updateStewardCommission->commissionLen; i++) {
        CHECK_ERROR(readBytes(&ctx, &address.ptr, address.len))
        CHECK_ERROR(readBytes(&ctx, &amount.ptr, amount.len))
    }
    updateStewardCommission->commission.len = ctx.offset - startOffset;

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readChangeValidatorMetadata(const bytes_t *data, tx_metadata_change_t *metadataChange) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    metadataChange->validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &metadataChange->validator.ptr, metadataChange->validator.len))

    uint32_t tmpValue = 0;
    // The validator email
    metadataChange->email.ptr = NULL;
    metadataChange->email.len = 0;
    uint8_t has_email = 0;
    CHECK_ERROR(readByte(&ctx, &has_email))
    if (has_email != 0 && has_email != 1) {
        return parser_value_out_of_range;
    }
    if (has_email) {
      CHECK_ERROR(readUint32(&ctx, &tmpValue));
      if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
      }
      metadataChange->email.len = (uint16_t)tmpValue;
      CHECK_ERROR(readBytes(&ctx, &metadataChange->email.ptr, metadataChange->email.len))
    }

    /// The validator description
    metadataChange->description.ptr = NULL;
    metadataChange->description.len = 0;
    uint8_t has_description = 0;
    CHECK_ERROR(readByte(&ctx, &has_description))
    if (has_description != 0 && has_description != 1) {
        return parser_value_out_of_range;
    }
    if (has_description) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->description.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->description.ptr, metadataChange->description.len))
    }

    /// The validator website
    metadataChange->website.ptr = NULL;
    metadataChange->website.len = 0;
    uint8_t has_website;
    CHECK_ERROR(readByte(&ctx, &has_website))
    if (has_website) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->website.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->website.ptr, metadataChange->website.len))
    }

    /// The validator's discord handle
    metadataChange->discord_handle.ptr = NULL;
    metadataChange->discord_handle.len = 0;
    uint8_t has_discord_handle;
    CHECK_ERROR(readByte(&ctx, &has_discord_handle))
    if (has_discord_handle) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->discord_handle.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->discord_handle.ptr, metadataChange->discord_handle.len))
    }

    /// The validator's avatar
    metadataChange->avatar.ptr = NULL;
    metadataChange->avatar.len = 0;
    uint8_t has_avatar;
    CHECK_ERROR(readByte(&ctx, &has_avatar))
    if (has_avatar) {
        CHECK_ERROR(readUint32(&ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        metadataChange->avatar.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->avatar.ptr, metadataChange->avatar.len))
    }

    // Commission rate
    CHECK_ERROR(readByte(&ctx, &metadataChange->has_commission_rate))
    if (metadataChange->has_commission_rate) {
        metadataChange->commission_rate.len = 32;
        CHECK_ERROR(readBytes(&ctx, &metadataChange->commission_rate.ptr, metadataChange->commission_rate.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readBridgePoolTransfer(const bytes_t *data, tx_bridge_pool_transfer_t *bridgePoolTransfer) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    CHECK_ERROR(readByte(&ctx, &bridgePoolTransfer->kind))
    if (bridgePoolTransfer->kind > Nut) {
         return parser_value_out_of_range;
    }

    bridgePoolTransfer->asset.len = ETH_ADDRESS_LEN;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->asset.ptr, bridgePoolTransfer->asset.len))

    bridgePoolTransfer->recipient.len = ETH_ADDRESS_LEN;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->recipient.ptr, bridgePoolTransfer->recipient.len))

    bridgePoolTransfer->sender.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->sender.ptr, bridgePoolTransfer->sender.len))

    bridgePoolTransfer->amount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->amount.ptr, bridgePoolTransfer->amount.len))

    bridgePoolTransfer->gasAmount.len = 32;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->gasAmount.ptr, bridgePoolTransfer->gasAmount.len))

    bridgePoolTransfer->gasPayer.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->gasPayer.ptr, bridgePoolTransfer->gasPayer.len))

    bridgePoolTransfer->gasToken.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &bridgePoolTransfer->gasToken.ptr, bridgePoolTransfer->gasToken.len))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readTimestamp(parser_context_t *ctx, timestamp_t *timestamp) {
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
    uint16_t tmpFieldLen = 0;
    CHECK_ERROR(readFieldSizeU16(&ctx, &tmpFieldLen))
    bytes_t tmpUrl = {.ptr = NULL, .len = (uint16_t)tmpFieldLen};
    CHECK_ERROR(readBytes(&ctx, &tmpUrl.ptr, tmpUrl.len))

    // Check value field (expect vector and check size)
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readFieldSizeU16(&ctx, &tmpFieldLen))

    if (tmpFieldLen != ctx.bufferLen - ctx.offset) {
        return parser_unexpected_buffer_end;
    }

    // Read port id
    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.port_id.len))
    CHECK_ERROR(readBytes(&ctx, &v->ibc.port_id.ptr, v->ibc.port_id.len))

    // Read channel id
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.channel_id.len))
    CHECK_ERROR(readBytes(&ctx, &v->ibc.channel_id.ptr, v->ibc.channel_id.len))

    ////// Packed data
    // Read token address
    CHECK_ERROR(checkTag(&ctx, 0x1A))
    CHECK_ERROR(readFieldSizeU16(&ctx, &tmpFieldLen))

    CHECK_ERROR(checkTag(&ctx, 0x0A))
    CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.token_address.len))
    CHECK_ERROR(readBytes(&ctx, &v->ibc.token_address.ptr, v->ibc.token_address.len))

    // Read token amount
    CHECK_ERROR(checkTag(&ctx, 0x12))
    CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.token_amount.len))
    CHECK_ERROR(readBytes(&ctx, &v->ibc.token_amount.ptr, v->ibc.token_amount.len))

    // Read sender
    CTX_CHECK_AVAIL(&ctx, 1);
    if (*(ctx.buffer + ctx.offset) == 0x22) {
        CHECK_ERROR(checkTag(&ctx, 0x22))
        CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.sender_address.len))
        CHECK_ERROR(readBytes(&ctx, &v->ibc.sender_address.ptr, v->ibc.sender_address.len))
    }

    // Read receiver
    CTX_CHECK_AVAIL(&ctx, 1);
    if (*(ctx.buffer + ctx.offset) == 0x2A) {
        CHECK_ERROR(checkTag(&ctx, 0x2A))
        CHECK_ERROR(readFieldSizeU16(&ctx, &v->ibc.receiver.len))
        CHECK_ERROR(readBytes(&ctx, &v->ibc.receiver.ptr, v->ibc.receiver.len))
    }
    ////////////////

    // Read timeout height
    CHECK_ERROR(checkTag(&ctx, 0x32))
    CHECK_ERROR(readByte(&ctx, &v->ibc.timeout_height_type))

    if (v->ibc.timeout_height_type > 0) {
        uint8_t consumed = 0;
        uint64_t tmp = 0;

        // Read 0x08
        CHECK_ERROR(checkTag(&ctx, 0x08))
        const uint64_t remainingBytes = ctx.bufferLen - ctx.offset;
        decodeLEB128(ctx.buffer + ctx.offset, remainingBytes, &consumed, &tmp);
        v->ibc.revision_number = tmp;
        ctx.offset += consumed;

        CHECK_ERROR(checkTag(&ctx, 0x10))
        const uint64_t remainingBytes2 = ctx.bufferLen - ctx.offset;
        decodeLEB128(ctx.buffer + ctx.offset, remainingBytes2, &consumed, &tmp);
        v->ibc.revision_height = tmp;
        ctx.offset += consumed;
    }
    // Read timeout timestamp
    CHECK_ERROR(readTimestamp(&ctx, &v->ibc.timeout_timestamp))

    if (ctx.offset < ctx.bufferLen) {
        CHECK_ERROR(checkTag(&ctx, 0x42))
        bytes_t  tmpBytes = {0};
        CHECK_ERROR(readFieldSizeU16(&ctx, &tmpBytes.len))
        CHECK_ERROR(readBytes(&ctx, &tmpBytes.ptr, tmpBytes.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    v->transaction.header.bytes.ptr = ctx->buffer + ctx->offset;
    v->transaction.header.extBytes.ptr = ctx->buffer + ctx->offset;
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

    uint32_t tmpValue = 0;
    // Timestamp
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    v->transaction.timestamp.len = (uint16_t)tmpValue;
    CHECK_ERROR(readBytes(ctx, &v->transaction.timestamp.ptr, v->transaction.timestamp.len))

    // Code hash
    v->transaction.header.codeHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // Data hash
    v->transaction.header.dataHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))

    // Memo hash
    v->transaction.header.memoHash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.memoHash.ptr, v->transaction.header.memoHash.len))

    v->transaction.header.bytes.len = ctx->offset - tmpOffset;

    CHECK_ERROR(checkTag(ctx, 0x01))
    // Fee.amount
    v->transaction.header.fees.amount.len = 32;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.amount.ptr, v->transaction.header.fees.amount.len))
    // Fee.denom
    CHECK_ERROR(readByte(ctx, &v->transaction.header.fees.denom))

    // Fee.address
    v->transaction.header.fees.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.address.ptr, v->transaction.header.fees.address.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transaction.header.fees.address, &v->transaction.header.fees.symbol))

    // Pubkey
    if (ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }
    const uint8_t pkType = *(ctx->buffer + ctx->offset);
    //Pubkey must include pkType (needed for encoding)
    v->transaction.header.pubkey.len = 1 + (pkType == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN);
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.pubkey.ptr, v->transaction.header.pubkey.len))

    // Epoch
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.epoch))
    // GasLimit
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.gasLimit))


    // Unshielded section hash
    uint8_t has_unshield_section_hash = 0;
    CHECK_ERROR(readByte(ctx, &has_unshield_section_hash))
    if (has_unshield_section_hash){
        v->transaction.header.unshieldSectionHash.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &v->transaction.header.unshieldSectionHash.ptr, v->transaction.header.unshieldSectionHash.len))
    }

    v->transaction.header.extBytes.len = ctx->offset - tmpOffset;

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

    CHECK_ERROR(readByte(ctx, &extraData->commitmentDiscriminant))
    if (extraData->commitmentDiscriminant) {
        uint32_t bytesLen = 0;
        CHECK_ERROR(readUint32(ctx, &bytesLen));
        if (bytesLen > UINT16_MAX) {
             return parser_value_out_of_range;
        }
        extraData->bytes.len = (uint16_t)bytesLen;
        CHECK_ERROR(readBytes(ctx, &extraData->bytes.ptr, extraData->bytes.len))
    } else {
        uint8_t const * code_hash;
        CHECK_ERROR(readBytes(ctx, &code_hash, HASH_LEN))
        MEMCPY(extraData->bytes_hash, code_hash, HASH_LEN);
    }

    extraData->tag.ptr = NULL;
    extraData->tag.len = 0;
    uint8_t has_tag = 0;
    CHECK_ERROR(readByte(ctx, &has_tag))
    if (has_tag != 0 && has_tag != 1) {
        return parser_value_out_of_range;
    }

    uint32_t tmpValue = 0;
    if (has_tag) {
        CHECK_ERROR(readUint32(ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        extraData->tag.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(ctx, &extraData->tag.ptr, extraData->tag.len))
    }

    if (crypto_computeCodeHash(extraData) != zxerr_ok) {
        return parser_unexpected_error;
    }

    return parser_ok;
}

static parser_error_t readSignatureSection(parser_context_t *ctx, signature_section_t *signature) {
    if (ctx == NULL || signature == NULL) {
        return parser_unexpected_error;
    }

    uint8_t sectionDiscriminant = 0;
    CHECK_ERROR(readByte(ctx, &sectionDiscriminant))
    if (sectionDiscriminant != DISCRIMINANT_SIGNATURE) {
        return parser_unexpected_value;
    }

    CHECK_ERROR(readUint32(ctx, &signature->hashes.hashesLen))
    signature->hashes.hashes.len = HASH_LEN * signature->hashes.hashesLen;
    CHECK_ERROR(readBytes(ctx, (const uint8_t **) &signature->hashes.hashes.ptr, signature->hashes.hashes.len))

    CHECK_ERROR(readByte(ctx, (uint8_t *) &signature->signerDiscriminant))
    switch (signature->signerDiscriminant) {
        case PubKeys:
        CHECK_ERROR(readUint32(ctx, &signature->pubKeysLen))
        signature->pubKeys.len = 0;
        CHECK_ERROR(readBytes(ctx, &signature->pubKeys.ptr, signature->pubKeys.len))
        for (uint32_t i = 0; i < signature->pubKeysLen; i++) {
            // Read the public key's tag
            uint8_t tag = 0;
            CHECK_ERROR(readByte(ctx, &tag))
            signature->pubKeys.len ++;
            if (tag != key_ed25519 && tag != key_secp256k1) {
                return parser_unexpected_value;
            }
            // Read the public key proper
            const uint8_t signatureSize = tag == key_ed25519 ? PK_LEN_25519 : COMPRESSED_SECP256K1_PK_LEN;
            uint8_t *tmpOutput = NULL;
            CHECK_ERROR(readBytes(ctx, (const uint8_t **) &tmpOutput, signatureSize));
            signature->pubKeys.len += signatureSize;
        }
        break;

        case Address:
        signature->address.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(ctx, &signature->address.ptr, signature->address.len))
        break;

        default:
            return parser_unexpected_value;
    }

    CHECK_ERROR(readUint32(ctx, &signature->signaturesLen))
    signature->indexedSignatures.len = 0;
    CHECK_ERROR(readBytes(ctx, &signature->indexedSignatures.ptr, signature->indexedSignatures.len))

    for (uint32_t i = 0; i < signature->signaturesLen; i++) {
        // Skip the signature's 1 byte index
        ctx->offset ++;
        signature->indexedSignatures.len ++;
        // Read the signature's tag
        uint8_t tag = 0;
        CHECK_ERROR(readByte(ctx, &tag))
        signature->indexedSignatures.len ++;
        if (tag != key_ed25519 && tag != key_secp256k1) {
                return parser_unexpected_value;
        }
        const uint8_t signatureSize = tag == key_ed25519 ? ED25519_SIGNATURE_SIZE : SIG_SECP256K1_LEN;
        uint8_t *tmpOutput = NULL;
        CHECK_ERROR(readBytes(ctx, (const uint8_t **) &tmpOutput, signatureSize));
        signature->indexedSignatures.len += signatureSize;
    }

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
    uint32_t tmpValue = 0;
    CHECK_ERROR(readUint32(ctx, &tmpValue));
    if (tmpValue > UINT16_MAX) {
        return parser_value_out_of_range;
    }
    data->bytes.len = (uint16_t)tmpValue;
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

    CHECK_ERROR(readByte(ctx, &code->commitmentDiscriminant))
    if (code->commitmentDiscriminant) {
      uint32_t bytesLen;
      CHECK_ERROR(readUint32(ctx, &bytesLen));
      code->bytes.len = bytesLen;
      CHECK_ERROR(readBytes(ctx, &code->bytes.ptr, code->bytes.len))
    } else {
      uint8_t const *code_hash;
      CHECK_ERROR(readBytes(ctx, &code_hash, HASH_LEN))
      MEMCPY(code->bytes_hash, code_hash, HASH_LEN);
    }

    code->tag.ptr = NULL;
    code->tag.len = 0;
    uint8_t has_tag = 0;
    CHECK_ERROR(readByte(ctx, &has_tag))
    if (has_tag != 0 && has_tag != 1) {
        return parser_value_out_of_range;
    }

    if (has_tag) {
        uint32_t tmpValue = 0;
        CHECK_ERROR(readUint32(ctx, &tmpValue));
        if (tmpValue > UINT16_MAX) {
            return parser_value_out_of_range;
        }
        code->tag.len = (uint16_t)tmpValue;
        CHECK_ERROR(readBytes(ctx, &code->tag.ptr, code->tag.len))
    }

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

static parser_error_t readMaspTx(parser_context_t *ctx, masp_tx_section_t *maspTx) {
    if (ctx == NULL) {
        return parser_unexpected_error;
    }
  uint8_t discriminant;
    CHECK_ERROR(readByte(ctx, &discriminant))
    if (discriminant != DISCRIMINANT_MASP_TX) {
        return parser_unexpected_value;
    }
  CHECK_ERROR(readTransaction(ctx, &maspTx->data))
    return parser_ok;
}

static parser_error_t readMaspBuilder(parser_context_t *ctx, section_t *maspBuilder) {
    if (ctx == NULL) {
        return parser_unexpected_error;
    }
    (void) maspBuilder;
    return parser_ok;
}

#if(0)
static parser_error_t readCiphertext(parser_context_t *ctx, section_t *ciphertext) {
    (void) ctx;
    (void) ciphertext;
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
    v->transaction.sections.signaturesLen = 0;

    mem_init();

    for (uint32_t i = 0; i < v->transaction.sections.sectionLen; i++) {
        if (ctx->offset >= ctx->bufferLen) {
            return parser_unexpected_error;
        }
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
            case DISCRIMINANT_SIGNATURE: {
                if (v->transaction.sections.signaturesLen >= MAX_SIGNATURE_SECS) {
                    return parser_value_out_of_range;
                }
                signature_section_t *signature = &v->transaction.sections.signatures[v->transaction.sections.signaturesLen++];
                CHECK_ERROR(readSignatureSection(ctx, signature))
                signature->idx = i+1;
                break;
            }
            case DISCRIMINANT_MASP_TX:
                CHECK_ERROR(readMaspTx(ctx, &v->transaction.sections.maspTx))
                break;

            case DISCRIMINANT_MASP_BUILDER:
                CHECK_ERROR(readMaspBuilder(ctx, NULL))
                break;
#if(0)
            case DISCRIMINANT_CIPHERTEXT:
                CHECK_ERROR(readCiphertext(ctx, &v->transaction.sections.ciphertext))
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

    txObj->transaction.header.memoSection = NULL;
    if (!isAllZeroes(txObj->transaction.header.memoHash.ptr, txObj->transaction.header.memoHash.len)) {
        const section_t *extra_data = txObj->transaction.sections.extraData;
        // Load the linked to data from the extra data sections
        for (uint32_t i = 0; i < txObj->transaction.sections.extraDataLen; i++) {
            uint8_t extraDataHash[HASH_LEN] = {0};
            if (crypto_hashExtraDataSection(&extra_data[i], extraDataHash, sizeof(extraDataHash)) != zxerr_ok) {
                return parser_unexpected_error;
            }

            if (!memcmp(extraDataHash, txObj->transaction.header.memoHash.ptr, HASH_LEN)) {
                // If this section contains the memo
                txObj->transaction.header.memoSection = &extra_data[i];
            }
        }
        if (txObj->transaction.header.memoSection == NULL) {
            return parser_unexpected_error;
        }
    }

    CHECK_ERROR(readTransactionType(&txObj->transaction.sections.code.tag, &txObj->typeTx))
    const section_t *data = &txObj->transaction.sections.data;
    switch (txObj->typeTx) {
        case Bond:
        case Unbond:
            CHECK_ERROR(readBondUnbond(&txObj->transaction.sections.data.bytes, txObj))
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
        case ClaimRewards:
        case Withdraw:
            CHECK_ERROR(readWithdrawTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case CommissionChange:
            CHECK_ERROR(readCommissionChangeTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case BecomeValidator:
            CHECK_ERROR(readBecomeValidator(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UpdateVP:
            CHECK_ERROR(readUpdateVPTxn(&txObj->transaction.sections.data.bytes, txObj->transaction.sections.extraData, txObj->transaction.sections.extraDataLen, txObj))
            break;
        case UnjailValidator:
            CHECK_ERROR(readUnjailValidator(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case IBC:
            CHECK_ERROR(readIBCTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case ReactivateValidator:
        case DeactivateValidator:
            CHECK_ERROR(readActivateValidator(&data->bytes, &txObj->activateValidator))
            break;
        case Redelegate:
            CHECK_ERROR(readRedelegate(&data->bytes, &txObj->redelegation))
            break;

        case ResignSteward:
            CHECK_ERROR(readResignSteward(&data->bytes, &txObj->resignSteward))
            break;

        case ChangeConsensusKey:
            CHECK_ERROR(readChangeConsensusKey(&data->bytes, &txObj->consensusKeyChange))
            break;

        case UpdateStewardCommission:
            CHECK_ERROR(readUpdateStewardCommission(&data->bytes, &txObj->updateStewardCommission))
            break;

        case ChangeValidatorMetadata:
            CHECK_ERROR(readChangeValidatorMetadata(&data->bytes, &txObj->metadataChange))
            break;

        case BridgePoolTransfer:
            CHECK_ERROR(readBridgePoolTransfer(&data->bytes, &txObj->bridgePoolTransfer))
            break;

        default:
            return parser_unexpected_method;
    }

    return  parser_ok;
}
