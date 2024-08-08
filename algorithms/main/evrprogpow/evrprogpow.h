/* ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
 * Copyright 2018-2019 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0.
 */

#pragma once

#include "../common/ethash/include/hash_types.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The Ethash algorithm revision implemented as specified in the Ethash spec
 * https://github.com/ethereum/wiki/wiki/Ethash.
 */
#define EVRPROGPOW_REVISION "23"

#define EVRPROGPOW_EPOCH_LENGTH 12000
#define EVRPROGPOW_LIGHT_CACHE_ITEM_SIZE 64
#define EVRPROGPOW_FULL_DATASET_ITEM_SIZE 128
#define EVRPROGPOW_NUM_DATASET_ACCESSES 64


struct evrprogpow_epoch_context
{
    const int epoch_number;
    const int light_cache_num_items;
    const union ethash_hash512* const light_cache;
    const uint32_t* const l1_cache;
    const int full_dataset_num_items;
};


struct evrprogpow_epoch_context_full;


struct evrprogpow_result
{
    union ethash_hash256 final_hash;
    union ethash_hash256 mix_hash;
};


/**
 * Calculates the number of items in the light cache for given epoch.
 *
 * This function will search for a prime number matching the criteria given
 * by the Ethash so the execution time is not constant. It takes ~ 0.01 ms.
 *
 * @param epoch_number  The epoch number.
 * @return              The number items in the light cache.
 */
int evrprogpow_calculate_light_cache_num_items(int epoch_number) NOEXCEPT;


/**
 * Calculates the number of items in the full dataset for given epoch.
 *
 * This function will search for a prime number matching the criteria given
 * by the Ethash so the execution time is not constant. It takes ~ 0.05 ms.
 *
 * @param epoch_number  The epoch number.
 * @return              The number items in the full dataset.
 */
int evrprogpow_calculate_full_dataset_num_items(int epoch_number) NOEXCEPT;

/**
 * Calculates the epoch seed hash.
 * @param epoch_number  The epoch number.
 * @return              The epoch seed hash.
 */
union ethash_hash256 evrprogpow_calculate_epoch_seed(int epoch_number) NOEXCEPT;


struct evrprogpow_epoch_context* evrprogpow_create_epoch_context(int epoch_number) NOEXCEPT;

/**
 * Creates the epoch context with the full dataset initialized.
 *
 * The memory for the full dataset is only allocated and marked as "not-generated".
 * The items of the full dataset are generated on the fly when hit for the first time.
 *
 * The memory allocated in the context MUST be freed with evrprogpow_destroy_epoch_context_full().
 *
 * @param epoch_number  The epoch number.
 * @return  Pointer to the context or null in case of memory allocation failure.
 */
struct evrprogpow_epoch_context_full* evrprogpow_create_epoch_context_full(int epoch_number) NOEXCEPT;

void evrprogpow_destroy_epoch_context(struct evrprogpow_epoch_context* context) NOEXCEPT;

void evrprogpow_destroy_epoch_context_full(struct evrprogpow_epoch_context_full* context) NOEXCEPT;


/**
 * Get global shared epoch context.
 */
const struct evrprogpow_epoch_context* evrprogpow_get_global_epoch_context(int epoch_number) NOEXCEPT;

/**
 * Get global shared epoch context with full dataset initialized.
 */
const struct evrprogpow_epoch_context_full* evrprogpow_get_global_epoch_context_full(
    int epoch_number) NOEXCEPT;


struct evrprogpow_result evrprogpow_hash(const struct evrprogpow_epoch_context* context,
    const union ethash_hash256* header_hash, uint64_t nonce) NOEXCEPT;

bool evrprogpow_verify(const struct evrprogpow_epoch_context* context,
    const union ethash_hash256* header_hash, const union ethash_hash256* mix_hash, uint64_t nonce,
    const union ethash_hash256* boundary) NOEXCEPT;

bool evrprogpow_verify_final_hash(const union ethash_hash256* header_hash,
    const union ethash_hash256* mix_hash, uint64_t nonce,
    const union ethash_hash256* boundary) NOEXCEPT;

#ifdef __cplusplus
}
#endif
