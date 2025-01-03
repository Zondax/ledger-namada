#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "keys_def.h"

/* Interface functions with jubjub crate */
parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);
parser_error_t randomized_secret_from_seed(const uint8_t ask[32], const uint8_t alpha[32], uint8_t output[32]);
parser_error_t compute_sbar(const uint8_t s[32], uint8_t r[32], uint8_t rsk[32], uint8_t sbar[32]);
parser_error_t add_points(const uint8_t hash[32], const uint8_t value[32], const uint8_t scalar[32], uint8_t cv[32]);
parser_error_t is_valid_diversifier(const uint8_t hash[32]);
void get_pkd(uint32_t zip32_account, const uint8_t *diversifier_ptr, uint8_t *pkd);
void zip32_child_ask_nsk(uint32_t account, uint8_t *ask, uint8_t *nsk);
void diversifier_find_valid(uint32_t zip32_account, uint8_t *default_diversifier);
void zip32_xfvk(uint32_t zip32_account, uint8_t *fvk_tag, uint8_t *chain_code, uint8_t *fvk, uint8_t *dk);
