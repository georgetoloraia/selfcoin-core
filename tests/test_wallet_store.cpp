#include "test_framework.hpp"

#include <filesystem>

#include "apps/selfcoin-wallet/wallet_store.hpp"

using namespace selfcoin::wallet;

TEST(test_wallet_store_persists_sent_events_and_notes) {
  const std::string wallet_file = "/tmp/selfcoin_wallet_store_test/wallet.json";
  std::filesystem::remove_all("/tmp/selfcoin_wallet_store_test");
  std::filesystem::create_directories("/tmp/selfcoin_wallet_store_test");

  {
    WalletStore store;
    ASSERT_TRUE(store.open(wallet_file));
    ASSERT_TRUE(store.add_sent_txid("abc123"));
    ASSERT_TRUE(store.append_local_event("event-one"));
    ASSERT_TRUE(store.append_local_event("event-two"));
    ASSERT_TRUE(store.upsert_mint_note("note-a", 250000000, true));
    ASSERT_TRUE(store.upsert_mint_note("note-b", 50000000, false));
    ASSERT_TRUE(store.set_mint_deposit_ref("dep-ref"));
    ASSERT_TRUE(store.set_mint_last_deposit_txid("txid1"));
    ASSERT_TRUE(store.set_mint_last_deposit_vout(3));
    ASSERT_TRUE(store.set_mint_last_redemption_batch_id("batch-9"));
  }

  WalletStore reload;
  ASSERT_TRUE(reload.open(wallet_file));
  WalletStore::State state;
  ASSERT_TRUE(reload.load(&state));

  ASSERT_EQ(state.sent_txids.size(), 1u);
  ASSERT_EQ(state.sent_txids[0], "abc123");
  ASSERT_EQ(state.local_events.size(), 2u);
  ASSERT_EQ(state.local_events[0], "event-one");
  ASSERT_EQ(state.local_events[1], "event-two");
  ASSERT_EQ(state.mint_notes.size(), 2u);
  ASSERT_EQ(state.mint_deposit_ref, "dep-ref");
  ASSERT_EQ(state.mint_last_deposit_txid, "txid1");
  ASSERT_EQ(state.mint_last_deposit_vout, 3u);
  ASSERT_EQ(state.mint_last_redemption_batch_id, "batch-9");
}
