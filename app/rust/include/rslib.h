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
bool is_valid_diversifier(const uint8_t hash[32]);
