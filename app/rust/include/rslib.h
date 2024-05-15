#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "keys_def.h"

/* Interface functions with jubjub crate */
parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);
parser_error_t get_default_diversifier_list(const uint8_t dk[32], uint8_t start_index[11], uint8_t d_l[44]);
parser_error_t get_default_diversifier(const uint8_t dk[32], uint8_t start_index[11], uint8_t d[11]);
parser_error_t get_pkd(const uint8_t ivk_ptr[32], const uint8_t hash[32], uint8_t pk_d[32]);
parser_error_t get_pkd(const uint8_t ivk_ptr[32], const uint8_t hash[32], uint8_t pk_d[32]);
bool is_valid_diversifier(const uint8_t hash[32]);
parser_error_t randomized_secret_from_seed(const uint8_t ask[32], const uint8_t alpha[32], uint8_t output[32]);
parser_error_t compute_sbar(const uint8_t s[32], uint8_t r[32], uint8_t rsk[32], uint8_t sbar[32]);
parser_error_t add_points(const uint8_t hash[32], const uint8_t value[32], const uint8_t scalar[32], uint8_t cv[32]);
