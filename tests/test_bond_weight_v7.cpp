#include "test_framework.hpp"

#include <limits>

#include "codec/bytes.hpp"
#include "consensus/sortition_v6.hpp"
#include "consensus/validators.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"

using namespace selfcoin;

namespace {

Bytes valreg_script(const PubKey32& pub) {
  Bytes out{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  out.insert(out.end(), pub.begin(), pub.end());
  return out;
}

Hash32 deterministic_output(std::uint64_t i) {
  codec::ByteWriter w;
  w.u64le(i);
  return crypto::sha256d(w.data());
}

Tx base_tx_with_valreg_output(std::uint64_t bond_value) {
  Tx tx;
  tx.version = 1;
  tx.lock_time = 0;
  tx.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});
  PubKey32 pub{};
  pub[0] = 42;
  tx.outputs.push_back(TxOut{bond_value, valreg_script(pub)});
  return tx;
}

}  // namespace

TEST(test_v7_reg_bond_min_enforced) {
  const Tx tx = base_tx_with_valreg_output(999);
  SpecialValidationContext ctx;
  ctx.consensus_version = 7;
  ctx.v7_min_bond_amount = 1000;
  ctx.v7_max_bond_amount = 5000;

  const auto r = validate_tx(tx, 1, UtxoSet{}, &ctx);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, "SCVALREG output out of v7 bond range");
}

TEST(test_v7_reg_bond_max_enforced) {
  const Tx tx = base_tx_with_valreg_output(6000);
  SpecialValidationContext ctx;
  ctx.consensus_version = 7;
  ctx.v7_min_bond_amount = 1000;
  ctx.v7_max_bond_amount = 5000;

  const auto r = validate_tx(tx, 1, UtxoSet{}, &ctx);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, "SCVALREG output out of v7 bond range");
}

TEST(test_v7_pre_v7_fixed_bond_path_unchanged) {
  const Tx tx = base_tx_with_valreg_output(BOND_AMOUNT + 1);
  SpecialValidationContext ctx;
  ctx.consensus_version = 6;
  const auto r = validate_tx(tx, 1, UtxoSet{}, &ctx);
  ASSERT_TRUE(!r.ok);
  ASSERT_EQ(r.error, "SCVALREG output must equal BOND_AMOUNT");
}

TEST(test_v7_effective_units_cap_applied) {
  consensus::ValidatorInfo info;
  info.status = consensus::ValidatorStatus::ACTIVE;
  info.has_bond = true;
  info.bonded_amount = 1'000'000;

  consensus::ValidatorWeightParamsV6 v6;
  v6.bond_unit = 10;
  v6.units_max = 1'000'000;
  consensus::ValidatorWeightParamsV7 v7;
  v7.effective_units_cap = 1234;

  const auto raw = consensus::validator_weight_units_v6(info, v6);
  const auto eff = consensus::validator_effective_weight_units_v7(info, v6, v7);
  ASSERT_TRUE(raw > v7.effective_units_cap);
  ASSERT_EQ(eff, v7.effective_units_cap);
}

TEST(test_v7_sortition_more_bond_more_eligibility_up_to_cap) {
  constexpr std::uint64_t total_weight = 1 + 10 + 50;
  const auto t_a = consensus::threshold_weighted_v6(total_weight, 1, 10, 1);
  const auto t_b = consensus::threshold_weighted_v6(total_weight, 10, 10, 1);
  const auto t_c = consensus::threshold_weighted_v6(total_weight, 50, 10, 1);

  std::size_t hits_a = 0;
  std::size_t hits_b = 0;
  std::size_t hits_c = 0;
  for (std::uint64_t i = 0; i < 4000; ++i) {
    const auto out = deterministic_output(i);
    if (consensus::eligible_weighted_v6(out, t_a)) ++hits_a;
    if (consensus::eligible_weighted_v6(out, t_b)) ++hits_b;
    if (consensus::eligible_weighted_v6(out, t_c)) ++hits_c;
  }

  ASSERT_TRUE(hits_b >= hits_a);
  ASSERT_TRUE(hits_c >= hits_b);
}

void register_bond_weight_v7_tests() {}
