// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "../common/ethash/ethash/bit_manipulation.h"
#include "../common/ethash/ethash/endianness.hpp"
#include "../common/ethash/ethash/kiss99.hpp"
#include "../common/ethash/include/keccak.hpp"
#include "evrprogpow_internal.hpp"
#include "evrprogpow_progpow.hpp"

#include <array>

namespace evrprogpow_progpow
{
namespace
{
/// A variant of Keccak hash function for ProgPoW.
///
/// This Keccak hash function uses 800-bit permutation (Keccak-f[800]) with 576 bitrate.
/// It take exactly 576 bits of input (split across 3 arguments) and adds no padding.
///
/// @param header_hash  The 256-bit header hash.
/// @param nonce        The 64-bit nonce.
/// @param mix_hash     Additional 256-bits of data.
/// @return             The 256-bit output of the hash function.
void keccak_progpow_256(uint32_t* st) noexcept
{
    ethash_keccakf800(st);
}

/// The same as keccak_progpow_256() but uses null mix
/// and returns top 64 bits of the output being a big-endian prefix of the 256-bit hash.
inline void keccak_progpow_64(uint32_t* st) noexcept
{
    keccak_progpow_256(st);
}


/// ProgPoW mix RNG state.
///
/// Encapsulates the state of the random number generator used in computing ProgPoW mix.
/// This includes the state of the KISS99 RNG and the precomputed random permutation of the
/// sequence of mix item indexes.
class mix_rng_state
{
public:
    inline explicit mix_rng_state(uint32_t* seed) noexcept;

    uint32_t next_dst() noexcept { return dst_seq[(dst_counter++) % num_regs]; }
    uint32_t next_src() noexcept { return src_seq[(src_counter++) % num_regs]; }

    kiss99 rng;

private:
    size_t dst_counter = 0;
    std::array<uint32_t, num_regs> dst_seq;
    size_t src_counter = 0;
    std::array<uint32_t, num_regs> src_seq;
};

mix_rng_state::mix_rng_state(uint32_t* hash_seed) noexcept
{
    const auto seed_lo = static_cast<uint32_t>(hash_seed[0]);
    const auto seed_hi = static_cast<uint32_t>(hash_seed[1]);

    const auto z = fnv1a(fnv_offset_basis, seed_lo);
    const auto w = fnv1a(z, seed_hi);
    const auto jsr = fnv1a(w, seed_lo);
    const auto jcong = fnv1a(jsr, seed_hi);

    rng = kiss99{z, w, jsr, jcong};

    // Create random permutations of mix destinations / sources.
    // Uses Fisher-Yates shuffle.
    for (uint32_t i = 0; i < num_regs; ++i)
    {
        dst_seq[i] = i;
        src_seq[i] = i;
    }

    for (uint32_t i = num_regs; i > 1; --i)
    {
        std::swap(dst_seq[i - 1], dst_seq[rng() % i]);
        std::swap(src_seq[i - 1], src_seq[rng() % i]);
    }
}


NO_SANITIZE("unsigned-integer-overflow")
inline uint32_t random_math(uint32_t a, uint32_t b, uint32_t selector) noexcept
{
    switch (selector % 11)
    {
    default:
    case 0:
        return a + b;
    case 1:
        return a * b;
    case 2:
        return mul_hi32(a, b);
    case 3:
        return std::min(a, b);
    case 4:
        return rotl32(a, b);
    case 5:
        return rotr32(a, b);
    case 6:
        return a & b;
    case 7:
        return a | b;
    case 8:
        return a ^ b;
    case 9:
        return clz32(a) + clz32(b);
    case 10:
        return popcount32(a) + popcount32(b);
    }
}

/// Merge data from `b` and `a`.
/// Assuming `a` has high entropy, only do ops that retain entropy even if `b`
/// has low entropy (i.e. do not do `a & b`).
NO_SANITIZE("unsigned-integer-overflow")
inline void random_merge(uint32_t& a, uint32_t b, uint32_t selector) noexcept
{
    const auto x = (selector >> 16) % 31 + 1;  // Additional non-zero selector from higher bits.
    switch (selector % 4)
    {
    case 0:
        a = (a * 33) + b;
        break;
    case 1:
        a = (a ^ b) * 33;
        break;
    case 2:
        a = rotl32(a, x) ^ b;
        break;
    case 3:
        a = rotr32(a, x) ^ b;
        break;
    }
}

static const uint32_t round_constants[22] = {
        0x00000001,0x00008082,0x0000808A,
        0x80008000,0x0000808B,0x80000001,
        0x80008081,0x00008009,0x0000008A,
        0x00000088,0x80008009,0x8000000A,
        0x8000808B,0x0000008B,0x00008089,
        0x00008003,0x00008002,0x00000080,
        0x0000800A,0x8000000A,0x80008081,
        0x00008080,
};

static const uint32_t evrmore_evrprogpow[15] = {
        0x00000045, //E
        0x00000056, //V
        0x00000052, //R
        0x0000004D, //M
        0x0000004F, //O
        0x00000052, //R
        0x00000045, //E
        0x0000002D, //-
        0x00000050, //P
        0x00000052, //R
        0x0000004F, //O
        0x00000047, //G
        0x00000050, //P
        0x0000004F, //O
        0x00000057, //W
};

using lookup_fn = ethash::hash2048 (*)(const epoch_context&, uint32_t);

using mix_array = std::array<std::array<uint32_t, num_regs>, num_lanes>;

void round(
    const epoch_context& context, uint32_t r, mix_array& mix, mix_rng_state state, lookup_fn lookup)
{
    const uint32_t num_items = static_cast<uint32_t>(context.full_dataset_num_items / 2);
    const uint32_t item_index = mix[r % num_lanes][0] % num_items;
    const ethash::hash2048 item = lookup(context, item_index);

    constexpr size_t num_words_per_lane = sizeof(item) / (sizeof(uint32_t) * num_lanes);
    constexpr int max_operations =
        num_cache_accesses > num_math_operations ? num_cache_accesses : num_math_operations;

    // Process lanes.
    for (int i = 0; i < max_operations; ++i)
    {
        if (i < num_cache_accesses)  // Random access to cached memory.
        {
            const auto src = state.next_src();
            const auto dst = state.next_dst();
            const auto sel = state.rng();

            for (size_t l = 0; l < num_lanes; ++l)
            {
                const size_t offset = mix[l][src] % l1_cache_num_items;
                random_merge(mix[l][dst], ethash::le::uint32(context.l1_cache[offset]), sel);
            }
        }
        if (i < num_math_operations)  // Random math.
        {
            // Generate 2 unique source indexes.
            const auto src_rnd = state.rng() % (num_regs * (num_regs - 1));
            const auto src1 = src_rnd % num_regs;  // O <= src1 < num_regs
            auto src2 = src_rnd / num_regs;        // 0 <= src2 < num_regs - 1
            if (src2 >= src1)
                ++src2;

            const auto sel1 = state.rng();
            const auto dst = state.next_dst();
            const auto sel2 = state.rng();

            for (size_t l = 0; l < num_lanes; ++l)
            {
                const uint32_t data = random_math(mix[l][src1], mix[l][src2], sel1);
                random_merge(mix[l][dst], data, sel2);
            }
        }
    }

    // DAG access pattern.
    uint32_t dsts[num_words_per_lane];
    uint32_t sels[num_words_per_lane];
    for (size_t i = 0; i < num_words_per_lane; ++i)
    {
        dsts[i] = i == 0 ? 0 : state.next_dst();
        sels[i] = state.rng();
    }

    // DAG access.
    for (size_t l = 0; l < num_lanes; ++l)
    {
        const auto offset = ((l ^ r) % num_lanes) * num_words_per_lane;
        for (size_t i = 0; i < num_words_per_lane; ++i)
        {
            const auto word = ethash::le::uint32(item.word32s[offset + i]);
            random_merge(mix[l][dsts[i]], word, sels[i]);
        }
    }
}

mix_array init_mix(uint32_t* hash_seed)
{
    const uint32_t z = fnv1a(fnv_offset_basis, static_cast<uint32_t>(hash_seed[0]));
    const uint32_t w = fnv1a(z, static_cast<uint32_t>(hash_seed[1]));

    mix_array mix;
    for (uint32_t l = 0; l < mix.size(); ++l)
    {
        const uint32_t jsr = fnv1a(w, l);
        const uint32_t jcong = fnv1a(jsr, l);
        kiss99 rng{z, w, jsr, jcong};

        for (auto& row : mix[l])
            row = rng();
    }
    return mix;
}

void hash_mix(
    const epoch_context& context, int block_number, uint32_t * seed, lookup_fn lookup, ethash::hash256 *mix_out_ptr) noexcept
{
    auto mix = init_mix(seed);
    auto number = uint64_t(block_number / period_length);
    uint32_t new_state[2];
    new_state[0] = number;
    new_state[1] = number >> 32;
    mix_rng_state state{new_state};

    for (uint32_t i = 0; i < 64; ++i)
        round(context, i, mix, state, lookup);

    // Reduce mix data to a single per-lane result.
    uint32_t lane_hash[num_lanes];
    for (size_t l = 0; l < num_lanes; ++l)
    {
        lane_hash[l] = fnv_offset_basis;
        for (uint32_t i = 0; i < num_regs; ++i)
            lane_hash[l] = fnv1a(lane_hash[l], mix[l][i]);
    }

    // Reduce all lanes to a single 256-bit result.
    static constexpr size_t num_words = sizeof(ethash::hash256) / sizeof(uint32_t);
    for (uint32_t& w : mix_out_ptr->word32s)
        w = fnv_offset_basis;
    for (size_t l = 0; l < num_lanes; ++l)
        mix_out_ptr->word32s[l % num_words] = fnv1a(mix_out_ptr->word32s[l % num_words], lane_hash[l]);
}
}  // namespace


void hash_one(const epoch_context& context, int block_number, const ethash::hash256 *header_hash,
    uint64_t nonce, ethash::hash256 *mix_out_ptr, ethash::hash256 *hash_out_ptr) noexcept
{
    uint32_t hash_seed[2];  // KISS99 initiator

    uint32_t state2[8];

    {
        uint32_t state[25] = {0x0};     // Keccak's state

        // Absorb phase for initial round of keccak
        // 1st fill with header data (8 words)
        for (int i = 0; i < 8; i++)
            state[i] = header_hash->word32s[i];

        // 2nd fill with nonce (2 words)
        state[8] = nonce;
        state[9] = nonce >> 32;

        // 3rd apply evrmore input constraints
        for (int i = 10; i < 25; i++)
            state[i] = evrmore_evrprogpow[i-10];

        keccak_progpow_64(state);

        for (int i = 0; i < 8; i++)
            state2[i] = state[i];
    }

    hash_seed[0] = state2[0];
    hash_seed[1] = state2[1];
    hash_mix(context, block_number, hash_seed, calculate_dataset_item_2048, mix_out_ptr);

    uint32_t state[25] = {0x0};     // Keccak's state

    // Absorb phase for last round of keccak (256 bits)
    // 1st initial 8 words of state are kept as carry-over from initial keccak
    for (int i = 0; i < 8; i++)
        state[i] = state2[i];

    // 2nd subsequent 8 words are carried from digest/mix
    for (int i = 8; i < 16; i++)
        state[i] = mix_out_ptr->word32s[i-8];

    // 3rd apply evrmore input constraints
    for (int i = 16; i < 25; i++)
        state[i] = evrmore_evrprogpow[i - 16];

    // Run keccak loop
    keccak_progpow_256(state);

    for (int i = 0; i < 8; ++i)
        hash_out_ptr->word32s[i] = ethash::le::uint32(state[i]);
}

bool verify(const epoch_context& context, int block_number, const ethash::hash256 *header_hash,
    const ethash::hash256& mix_hash, uint64_t nonce, ethash::hash256 *hash_out) noexcept
{
    uint32_t hash_seed[2];  // KISS99 initiator
    uint32_t state2[8];

    {
        // Absorb phase for initial round of keccak
        uint32_t state[25] = {0x0};     // Keccak's state
        // 1st fill with header data (8 words)
        for (int i = 0; i < 8; i++)
            state[i] = header_hash->word32s[i];

        // 2nd fill with nonce (2 words)
        state[8] = nonce;
        state[9] = nonce >> 32;

        // 3rd apply evrmore input constraints
        for (int i = 10; i < 25; i++)
            state[i] = evrmore_evrprogpow[i-10];

        keccak_progpow_64(state);

        for (int i = 0; i < 8; i++)
            state2[i] = state[i];
    }

    hash_seed[0] = state2[0];
    hash_seed[1] = state2[1];

    uint32_t state[25] = {0x0};     // Keccak's state

    // Absorb phase for last round of keccak (256 bits)
    // 1st initial 8 words of state are kept as carry-over from initial keccak
    for (int i = 0; i < 8; i++)
        state[i] = state2[i];


    // 2nd subsequent 8 words are carried from digest/mix
    for (int i = 8; i < 16; i++)
        state[i] = mix_hash.word32s[i-8];

    // 3rd apply evrmore input constraints
    for (int i = 16; i < 25; i++)
        state[i] = evrmore_evrprogpow[i - 16];

    // Run keccak loop
    keccak_progpow_256(state);

    for (int i = 0; i < 8; ++i)
        hash_out->word32s[i] = ethash::le::uint32(state[i]);

    ethash::hash256 expected_mix_hash;
    hash_mix(context, block_number, hash_seed, calculate_dataset_item_2048, &expected_mix_hash);

    return is_equal(expected_mix_hash, mix_hash);
}

}  // namespace evrprogpow_progpow
