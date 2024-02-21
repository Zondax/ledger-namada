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
#include "parser_address.h"
#include "parser_impl_common.h"
#include "bech32.h"

parser_error_t readAddressEstablished(parser_context_t *ctx, EstablishedAddress *obj) {
    obj->hash.len = 20;
    CHECK_ERROR(readBytes(ctx, &obj->hash.ptr, obj->hash.len))
    return parser_ok;
}

parser_error_t readAddressImplicit(parser_context_t *ctx, ImplicitAddress *obj) {
    obj->pubKeyHash.len = 20;
    CHECK_ERROR(readBytes(ctx, &obj->pubKeyHash.ptr, obj->pubKeyHash.len))
  return parser_ok;
}

parser_error_t readInternalAddressErc20(parser_context_t *ctx, InternalAddressErc20 *obj) {
    obj->erc20Addr.len = 20;
    CHECK_ERROR(readBytes(ctx, &obj->erc20Addr.ptr, obj->erc20Addr.len))
    return parser_ok;
}

parser_error_t readInternalAddressIbcToken(parser_context_t *ctx, InternalAddressIbcToken *obj) {
    obj->ibcTokenHash.len = 20;
    CHECK_ERROR(readBytes(ctx, &obj->ibcTokenHash.ptr, obj->ibcTokenHash.len))
    return parser_ok;
}

parser_error_t readInternalAddressNut(parser_context_t *ctx, InternalAddressNut *obj) {
    obj->ethAddr.len = 20;
    CHECK_ERROR(readBytes(ctx, &obj->ethAddr.ptr, obj->ethAddr.len))
    return parser_ok;
}

parser_error_t readAddressInternal(parser_context_t *ctx, InternalAddress *obj) {
    CHECK_ERROR(readByte(ctx, &obj->tag))
    switch(obj->tag) {
        case 0: //Pos
        case 1: //PosSlashPool
        case 2: //Parameters
        case 3: //Ibc
        case 5: //Governance
        case 6: //EthBridge
        case 7: //BridgePool
        case 10: //Multitoken
        case 11: //Pgf
        case 12: //Masp
        case 13: //TempStorage
            break;
        case 4:
            CHECK_ERROR(readInternalAddressIbcToken(ctx, &obj->IbcToken))
            break;
        case 8:
            CHECK_ERROR(readInternalAddressErc20(ctx, &obj->Erc20))
            break;
        case 9:
            CHECK_ERROR(readInternalAddressNut(ctx, &obj->Nut))
            break;
    }
    return parser_ok;
}

parser_error_t readAddressAlt(parser_context_t *ctx, AddressAlt *obj) {
    CHECK_ERROR(readByte(ctx, &obj->tag))
    switch(obj->tag) {
    case 0:
    CHECK_ERROR(readAddressEstablished(ctx, &obj->Established))
    break;
    case 1:
    CHECK_ERROR(readAddressImplicit(ctx, &obj->Implicit))
    break;
    case 2:
    CHECK_ERROR(readAddressInternal(ctx, &obj->Internal))
    break;
    }
    return parser_ok;
}

parser_error_t encodeAddress(const AddressAlt *addr, char *address, uint16_t addressLen) {
    uint8_t tmpBuffer[ADDRESS_LEN_BYTES] = {0};

    switch (addr->tag) {
        case 0:
            tmpBuffer[0] = PREFIX_ESTABLISHED;
            MEMCPY(tmpBuffer + 1, addr->Established.hash.ptr, 20);
            break;
        case 1:
            tmpBuffer[0] = PREFIX_IMPLICIT;
            MEMCPY(tmpBuffer + 1, addr->Implicit.pubKeyHash.ptr, 20);
            break;
        case 2:
            switch (addr->Internal.tag) {
            case 0:
              tmpBuffer[0] = PREFIX_POS;
              break;
            case 1:
              tmpBuffer[0] = PREFIX_SLASH_POOL;
              break;
            case 2:
              tmpBuffer[0] = PREFIX_PARAMETERS;
              break;
            case 3:
              tmpBuffer[0] = PREFIX_IBC;
              break;
            case 4:
              tmpBuffer[0] = PREFIX_IBC_TOKEN;
              MEMCPY(tmpBuffer + 1, addr->Internal.IbcToken.ibcTokenHash.ptr, 20);
              break;
            case 5:
              tmpBuffer[0] = PREFIX_GOVERNANCE;
              break;
            case 6:
              tmpBuffer[0] = PREFIX_ETH_BRIDGE;
              break;
            case 7:
              tmpBuffer[0] = PREFIX_BRIDGE_POOL;
              break;
            case 8:
              tmpBuffer[0] = PREFIX_ERC20;
              MEMCPY(tmpBuffer + 1, addr->Internal.Erc20.erc20Addr.ptr, 20);
              break;
            case 9:
              tmpBuffer[0] = PREFIX_NUT;
              MEMCPY(tmpBuffer + 1, addr->Internal.Nut.ethAddr.ptr, 20);
              break;
            case 10:
              tmpBuffer[0] = PREFIX_MULTITOKEN;
              break;
            case 11:
              tmpBuffer[0] = PREFIX_PGF;
              break;
            case 12:
              tmpBuffer[0] = PREFIX_MASP;
              break;
            case 13:
              tmpBuffer[0] = PREFIX_TMP_STORAGE;
              break;
            }
            break;

        default:
            return parser_value_out_of_range;
    }

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
