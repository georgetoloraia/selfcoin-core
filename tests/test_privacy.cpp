#include "test_framework.hpp"

#include "privacy/mint_client.hpp"

using namespace selfcoin;

TEST(test_mint_client_json_roundtrips) {
  privacy::MintDepositRegistrationRequest req;
  req.chain = "mainnet";
  req.deposit_txid.fill(0x11);
  req.deposit_vout = 3;
  req.mint_id.fill(0x22);
  req.recipient_pubkey_hash.fill(0x33);
  req.amount = 42'000;

  const auto json = privacy::to_json(req);
  ASSERT_TRUE(json.find("\"deposit_vout\":3") != std::string::npos);
  ASSERT_TRUE(json.find("\"amount\":42000") != std::string::npos);

  const auto dep_resp = privacy::parse_mint_deposit_registration_response(
      "{\"accepted\":true,\"confirmations_required\":2,\"mint_deposit_ref\":\"ref-1\"}");
  ASSERT_TRUE(dep_resp.has_value());
  ASSERT_TRUE(dep_resp->accepted);
  ASSERT_EQ(dep_resp->confirmations_required, 2u);
  ASSERT_EQ(dep_resp->mint_deposit_ref, "ref-1");

  const auto issue_resp =
      privacy::parse_mint_blind_issue_response("{\"signed_blinds\":[\"aa\",\"bb\"],\"mint_epoch\":7}");
  ASSERT_TRUE(issue_resp.has_value());
  ASSERT_EQ(issue_resp->signed_blinds.size(), 2u);
  ASSERT_EQ(issue_resp->mint_epoch, 7u);

  const auto redeem_resp =
      privacy::parse_mint_redemption_response("{\"accepted\":false,\"redemption_batch_id\":\"batch-9\"}");
  ASSERT_TRUE(redeem_resp.has_value());
  ASSERT_TRUE(!redeem_resp->accepted);
  ASSERT_EQ(redeem_resp->redemption_batch_id, "batch-9");

  const auto status_resp =
      privacy::parse_mint_redemption_status_response("{\"state\":\"finalized\",\"l1_txid\":\"deadbeef\"}");
  ASSERT_TRUE(status_resp.has_value());
  ASSERT_EQ(status_resp->state, "finalized");
  ASSERT_EQ(status_resp->l1_txid, "deadbeef");
}

void register_privacy_tests() {}
