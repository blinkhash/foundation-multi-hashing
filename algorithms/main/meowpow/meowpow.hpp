// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
///
/// API design decisions:
///
/// 1. Signed integer type is used whenever the size of the type is not
///    restricted by the Ethash specification.
///    See http://www.aristeia.com/Papers/C++ReportColumns/sep95.pdf.
///    See https://stackoverflow.com/questions/10168079/why-is-size-t-unsigned/.
///    See https://github.com/Microsoft/GSL/issues/171.

#pragma once

#include "meowpow.h"
#include "../common/ethash/include/hash_types.hpp"

#include <cstdint>
#include <cstring>
#include <memory>

namespace meowpow_main
{
constexpr auto revision = MEOWPOW_REVISION;

static constexpr int epoch_length = MEOWPOW_EPOCH_LENGTH;
static constexpr int light_cache_item_size = MEOWPOW_LIGHT_CACHE_ITEM_SIZE;
static constexpr int full_dataset_item_size = MEOWPOW_FULL_DATASET_ITEM_SIZE;
static constexpr int num_dataset_accesses = MEOWPOW_NUM_DATASET_ACCESSES;

using epoch_context = meowpow_epoch_context;
using epoch_context_full = meowpow_epoch_context_full;

using result = meowpow_result;

/// Constructs a 256-bit hash from an array of bytes.
///
/// @param bytes  A pointer to array of at least 32 bytes.
/// @return       The constructed hash.
inline ethash::hash256 hash256_from_bytes(const uint8_t bytes[32]) noexcept
{
    ethash::hash256 h;
    std::memcpy(&h, bytes, sizeof(h));
    return h;
}

struct search_result
{
    bool solution_found = false;
    uint64_t nonce = 0;
    ethash::hash256 final_hash = {};
    ethash::hash256 mix_hash = {};

    search_result() noexcept = default;

    search_result(result res, uint64_t n) noexcept
      : solution_found(true), nonce(n), final_hash(res.final_hash), mix_hash(res.mix_hash)
    {}
};


/// Alias for meowpow_calculate_light_cache_num_items().
static constexpr auto calculate_light_cache_num_items = meowpow_calculate_light_cache_num_items;

/// Alias for meowpow_calculate_full_dataset_num_items().
static constexpr auto calculate_full_dataset_num_items = meowpow_calculate_full_dataset_num_items;

/// Alias for meowpow_calculate_epoch_seed().
static constexpr auto calculate_epoch_seed = meowpow_calculate_epoch_seed;


/// Calculates the epoch number out of the block number.
inline constexpr int get_epoch_number(int block_number) noexcept
{
    return block_number ? block_number / epoch_length : 0;
}

/**
 * Coverts the number of items of a light cache to size in bytes.
 *
 * @param num_items  The number of items in the light cache.
 * @return           The size of the light cache in bytes.
 */
inline constexpr size_t get_light_cache_size(int num_items) noexcept
{
    return static_cast<size_t>(num_items) * light_cache_item_size;
}

/**
 * Coverts the number of items of a full dataset to size in bytes.
 *
 * @param num_items  The number of items in the full dataset.
 * @return           The size of the full dataset in bytes.
 */
inline constexpr uint64_t get_full_dataset_size(int num_items) noexcept
{
    return static_cast<uint64_t>(num_items) * full_dataset_item_size;
}

/// Owned unique pointer to an epoch context.
using epoch_context_ptr = std::unique_ptr<epoch_context, decltype(&meowpow_destroy_epoch_context)>;

using epoch_context_full_ptr =
    std::unique_ptr<epoch_context_full, decltype(&meowpow_destroy_epoch_context_full)>;

/// Creates Ethash epoch context.
///
/// This is a wrapper for meowpow_create_epoch_number C function that returns
/// the context as a smart pointer which handles the destruction of the context.
inline epoch_context_ptr create_epoch_context(int epoch_number) noexcept
{
    return {meowpow_create_epoch_context(epoch_number), meowpow_destroy_epoch_context};
}

inline epoch_context_full_ptr create_epoch_context_full(int epoch_number) noexcept
{
    return {meowpow_create_epoch_context_full(epoch_number), meowpow_destroy_epoch_context_full};
}


inline result hash(
    const epoch_context& context, const ethash::hash256& header_hash, uint64_t nonce) noexcept
{
    return meowpow_hash(&context, &header_hash, nonce);
}

result hash(const epoch_context_full& context, const ethash::hash256& header_hash, uint64_t nonce) noexcept;

inline bool verify_final_hash(const ethash::hash256& header_hash, const ethash::hash256& mix_hash, uint64_t nonce,
    const ethash::hash256& boundary) noexcept
{
    return meowpow_verify_final_hash(&header_hash, &mix_hash, nonce, &boundary);
}

inline bool verify(const epoch_context& context, const ethash::hash256& header_hash, const ethash::hash256& mix_hash,
    uint64_t nonce, const ethash::hash256& boundary) noexcept
{
    return meowpow_verify(&context, &header_hash, &mix_hash, nonce, &boundary);
}

search_result search_light(const epoch_context& context, const ethash::hash256& header_hash,
    const ethash::hash256& boundary, uint64_t start_nonce, size_t iterations) noexcept;

search_result search(const epoch_context_full& context, const ethash::hash256& header_hash,
    const ethash::hash256& boundary, uint64_t start_nonce, size_t iterations) noexcept;


/// Tries to find the epoch number matching the given seed hash.
///
/// Mining pool protocols (many variants of stratum and "getwork") send out
/// seed hash instead of epoch number to workers. This function tries to recover
/// the epoch number from this seed hash.
///
/// @param seed  Ethash seed hash.
/// @return      The epoch number or -1 if not found.
int find_epoch_number(const ethash::hash256& seed) noexcept;


/// Get global shared epoch context.
inline const epoch_context& get_global_epoch_context(int epoch_number) noexcept
{
    return *meowpow_get_global_epoch_context(epoch_number);
}

/// Get global shared epoch context with full dataset initialized.
inline const epoch_context_full& get_global_epoch_context_full(int epoch_number) noexcept
{
    return *meowpow_get_global_epoch_context_full(epoch_number);
}
}  // namespace meowpow_main
