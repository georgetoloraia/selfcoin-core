#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "common/types.hpp"

namespace selfcoin::consensus {

constexpr std::uint64_t BASE_UNITS_PER_COIN = 100'000'000ULL;
constexpr std::uint64_t TOTAL_SUPPLY_COINS = 7'000'000ULL;
constexpr std::uint64_t TOTAL_SUPPLY_UNITS = TOTAL_SUPPLY_COINS * BASE_UNITS_PER_COIN;
constexpr std::uint64_t BLOCK_TIME_TARGET_SECONDS = 180ULL;
constexpr std::uint64_t BLOCKS_PER_YEAR_365 = 175'200ULL;
constexpr std::uint64_t EMISSION_BLOCKS = 3'504'000ULL;
constexpr std::uint64_t EMISSION_Q = TOTAL_SUPPLY_UNITS / EMISSION_BLOCKS;
constexpr std::uint64_t EMISSION_R = TOTAL_SUPPLY_UNITS % EMISSION_BLOCKS;

struct Payout {
  std::uint64_t leader{0};
  std::vector<std::pair<PubKey32, std::uint64_t>> signers;  // sorted signer pubkey order
  std::uint64_t total{0};
};

std::uint64_t reward_units(std::uint64_t height);
Payout compute_payout(std::uint64_t height, std::uint64_t fees_units, const PubKey32& leader_pubkey,
                      std::vector<PubKey32> signer_pubkeys);

}  // namespace selfcoin::consensus
