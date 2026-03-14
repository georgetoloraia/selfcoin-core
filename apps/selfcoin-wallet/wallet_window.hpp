#pragma once

#include <optional>
#include <string>
#include <vector>

#include <QMainWindow>
#include <QStringList>

#include "common/types.hpp"

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
  void save_wallet_local_state() const;
  void load_wallet_local_state();

  void create_wallet();
  void open_wallet();
  void import_wallet();
  void export_wallet_secret();
  void save_connection_settings();
  void validate_send_form();
  void show_mint_info(const QString& action_name);
  void submit_send();

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
  QLabel* mint_status_label_{nullptr};

  QLineEdit* lightserver_url_edit_{nullptr};
  QLineEdit* mint_url_edit_{nullptr};
  QLabel* connection_summary_label_{nullptr};

  std::optional<LoadedWallet> wallet_;
  std::vector<WalletUtxo> utxos_;
  QStringList history_lines_;
  std::vector<std::string> local_sent_txids_;
  std::uint64_t tip_height_{0};
};

}  // namespace selfcoin::wallet
