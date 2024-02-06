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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "parser_txdef.h"

#include <stdint.h>

static const txn_types_t allowed_txn[] = {
    {"tx_bond.wasm", Bond},
    {"tx_unbond.wasm", Unbond},
    {"tx_redelegate.wasm", Redelegate},
    {"tx_init_account.wasm", InitAccount},
    {"tx_init_proposal.wasm", InitProposal},
    {"tx_vote_proposal.wasm", VoteProposal},
    {"tx_become_validator.wasm", BecomeValidator},
    {"tx_reveal_pk.wasm", RevealPubkey},
    {"tx_transfer.wasm", Transfer},
    {"tx_update_account.wasm", UpdateVP},
    {"tx_withdraw.wasm", Withdraw},
    {"tx_change_validator_commission.wasm", CommissionChange},
    {"tx_unjail_validator.wasm", UnjailValidator},
    {"tx_ibc.wasm", IBC},
    {"tx_deactivate_validator.wasm", DeactivateValidator},
    {"tx_reactivate_validator.wasm", ReactivateValidator},
    {"tx_claim_rewards.wasm", ClaimRewards},
    {"tx_resign_steward.wasm", ResignSteward},
    {"tx_change_consensus_key.wasm", ChangeConsensusKey},
    {"tx_update_steward_commission.wasm", UpdateStewardCommission},
    {"tx_change_validator_metadata.wasm", ChangeValidatorMetadata},
    {"tx_bridge_pool.wasm", BridgePoolTransfer},
};

static const uint32_t allowed_txn_len = sizeof(allowed_txn) / sizeof(allowed_txn[0]);

#ifdef __cplusplus
}
#endif
