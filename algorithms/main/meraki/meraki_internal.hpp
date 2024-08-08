// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
/// Contains declarations of internal ethash functions to allow them to be
/// unit-tested.

#pragma once

#include "meraki.hpp"
#include "../common/ethash/ethash/endianness.hpp"

#include <memory>
#include <vector>

extern "C" struct meraki_epoch_context_full : meraki_epoch_context
{
    ethash_hash1024* full_dataset;

    constexpr meraki_epoch_context_full(int epoch, int light_num_items,
        const ethash::hash512* light, const uint32_t* l1, int dataset_num_items,
        ethash_hash1024* dataset) noexcept
      : meraki_epoch_context{epoch, light_num_items, light, l1, dataset_num_items},
        full_dataset{dataset}
    {}
};

namespace meraki_main
{
inline bool is_less_or_equal(const ethash::hash256& a, const ethash::hash256& b) noexcept
{
    for (size_t i = 0; i < (sizeof(a) / sizeof(a.word64s[0])); ++i)
    {
        if (ethash::be::uint64(a.word64s[i]) > ethash::be::uint64(b.word64s[i]))
            return false;
        if (ethash::be::uint64(a.word64s[i]) < ethash::be::uint64(b.word64s[i]))
            return true;
    }
    return true;
}

inline bool is_equal(const ethash::hash256& a, const ethash::hash256& b) noexcept
{
    return std::memcmp(a.bytes, b.bytes, sizeof(a)) == 0;
}

void build_light_cache(ethash::hash512 cache[], int num_items, const ethash::hash256& seed) noexcept;

ethash::hash512 calculate_dataset_item_512(const epoch_context& context, int64_t index) noexcept;
ethash::hash1024 calculate_dataset_item_1024(const epoch_context& context, uint32_t index) noexcept;
ethash::hash2048 calculate_dataset_item_2048(const epoch_context& context, uint32_t index) noexcept;

namespace generic
{
using hash_fn_512 = ethash::hash512 (*)(const uint8_t* data, size_t size);
using build_light_cache_fn = void (*)(ethash::hash512 cache[], int num_items, const ethash::hash256& seed);

void build_light_cache(
    hash_fn_512 hash_fn, ethash::hash512 cache[], int num_items, const ethash::hash256& seed) noexcept;

epoch_context_full* create_epoch_context(
    build_light_cache_fn build_fn, int epoch_number, bool full) noexcept;

}  // namespace generic

}  // namespace meraki_main
