#pragma once

#include <optional>
#include <string>
#include <vector>

#include <QMainWindow>
#include <QStringList>

#include "common/types.hpp"
#include "wallet_store.hpp"

class QLabel;
class QLineEdit;
class QPushButton;
class QPlainTextEdit;
class QTabWidget;

namespace selfcoin::keystore {
struct ValidatorKey;
}

namespace selfcoin::wallet {

class WalletWindow final : public QMainWindow {
 public:
  struct MintNote {
    QString note_ref;
    std::uint64_t amount{0};
  };

  WalletWindow();

 private:
  struct LoadedWallet {
    std::string file_path;
    std::string passphrase;
    std::string network_name;
    std::string address;
    std::string pubkey_hex;
  };

  struct WalletUtxo {
    std::string txid_hex;
    std::uint32_t vout{0};
    std::uint64_t value{0};
    std::uint64_t height{0};
    selfcoin::Bytes script_pubkey;
  };

  void build_ui();
  void load_settings();
  void save_settings() const;
  void update_wallet_views();
  void update_connection_views();
  void refresh_chain_state(bool interactive);
  void render_history_view();
  void render_mint_state();
  void save_wallet_local_state();
  void load_wallet_local_state();
  bool open_wallet_store();
  void append_local_event(const QString& line);

  void create_wallet();
  void open_wallet();
  void import_wallet();
  void export_wallet_secret();
  void save_connection_settings();
  void validate_send_form();
  void submit_send();
  void submit_mint_deposit();
  void issue_mint_note();
  void submit_mint_redemption();
  void refresh_mint_redemption_status();

  std::optional<LoadedWallet> load_wallet_file(const QString& path, const QString& passphrase);
  std::optional<QString> prompt_passphrase(const QString& title, bool confirm) const;
  bool ensure_wallet_loaded(const QString& action_name);
  std::optional<selfcoin::keystore::ValidatorKey> load_wallet_key(std::string* err) const;

  QTabWidget* tabs_{nullptr};

  QLabel* wallet_status_label_{nullptr};
  QLabel* wallet_file_label_{nullptr};
  QLabel* network_label_{nullptr};
  QLabel* balance_label_{nullptr};
  QLabel* pending_balance_label_{nullptr};
  QLabel* receive_address_home_label_{nullptr};
  QLabel* receive_address_label_{nullptr};
  QPlainTextEdit* history_view_{nullptr};
  QLabel* tip_status_label_{nullptr};

  QLineEdit* send_address_edit_{nullptr};
  QLineEdit* send_amount_edit_{nullptr};
  QLineEdit* send_fee_edit_{nullptr};

  QLineEdit* mint_deposit_amount_edit_{nullptr};
  QLineEdit* mint_redeem_amount_edit_{nullptr};
  QLineEdit* mint_redeem_address_edit_{nullptr};
  QLineEdit* mint_issue_amount_edit_{nullptr};
  QLabel* mint_deposit_ref_label_{nullptr};
  QLabel* mint_notes_label_{nullptr};
  QLabel* mint_redemption_label_{nullptr};
  QLabel* mint_status_label_{nullptr};

  QLineEdit* lightserver_url_edit_{nullptr};
  QLineEdit* mint_url_edit_{nullptr};
  QLineEdit* mint_id_edit_{nullptr};
  QLabel* connection_summary_label_{nullptr};

  std::optional<LoadedWallet> wallet_;
  std::vector<WalletUtxo> utxos_;
  QStringList local_history_lines_;
  QStringList chain_history_lines_;
  std::vector<std::string> local_sent_txids_;
  std::uint64_t tip_height_{0};
  QString mint_deposit_ref_;
  QString mint_last_deposit_txid_;
  std::uint32_t mint_last_deposit_vout_{0};
  QString mint_last_redemption_batch_id_;
  std::vector<MintNote> mint_notes_;
  WalletStore store_;
};

}  // namespace selfcoin::wallet
