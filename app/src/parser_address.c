/*******************************************************************************
*  (c) 2018 - 2024 Zondax AG
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
