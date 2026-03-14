#include "wallet_window.hpp"

#include <array>
#include <algorithm>
#include <optional>
#include <set>
#include <sstream>
#include <string>

#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include "address/address.hpp"
#include "common/types.hpp"
#include "consensus/monetary.hpp"
#include "crypto/hash.hpp"
#include "keystore/validator_keystore.hpp"
#include "lightserver/client.hpp"
#include "utxo/signing.hpp"
#include "utxo/tx.hpp"

namespace selfcoin::wallet {
namespace {

constexpr const char* kSettingsOrg = "selfcoin";
constexpr const char* kSettingsApp = "reference-wallet";

std::optional<std::array<std::uint8_t, 32>> decode_hex32_string(const std::string& hex) {
  auto bytes = selfcoin::hex_decode(hex);
  if (!bytes || bytes->size() != 32) return std::nullopt;
  std::array<std::uint8_t, 32> out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}

QString elide_middle(const QString& value, int keep = 14) {
  if (value.size() <= keep * 2) return value;
  return value.left(keep) + "..." + value.right(keep);
}

std::optional<std::uint64_t> parse_coin_amount(const QString& value) {
  const QString trimmed = value.trimmed();
  if (trimmed.isEmpty()) return std::nullopt;
  const QStringList parts = trimmed.split('.');
  if (parts.size() > 2) return std::nullopt;
  bool whole_ok = false;
  const std::uint64_t whole = parts[0].isEmpty() ? 0 : parts[0].toULongLong(&whole_ok);
  if (!whole_ok && !parts[0].isEmpty()) return std::nullopt;
  std::uint64_t units = whole * consensus::BASE_UNITS_PER_COIN;
  if (parts.size() == 2) {
    QString frac = parts[1];
    if (frac.size() > 8) return std::nullopt;
    while (frac.size() < 8) frac.append('0');
    bool frac_ok = false;
    const std::uint64_t frac_units = frac.isEmpty() ? 0 : frac.toULongLong(&frac_ok);
    if (!frac_ok) return std::nullopt;
    units += frac_units;
  }
  return units;
}

QString format_coin_amount(std::uint64_t units) {
  const std::uint64_t whole = units / consensus::BASE_UNITS_PER_COIN;
  const std::uint64_t frac = units % consensus::BASE_UNITS_PER_COIN;
  if (frac == 0) return QString::number(whole) + " SC";
  QString frac_str = QString("%1").arg(frac, 8, 10, QChar('0'));
  while (frac_str.endsWith('0')) frac_str.chop(1);
  return QString("%1.%2 SC").arg(whole).arg(frac_str);
}

Hash32 wallet_scripthash_from_address(const std::string& address) {
  auto decoded = selfcoin::address::decode(address);
  if (!decoded) return zero_hash();
  return crypto::sha256(selfcoin::address::p2pkh_script_pubkey(decoded->pubkey_hash));
}

}  // namespace

WalletWindow::WalletWindow() {
  build_ui();
  load_settings();
  update_wallet_views();
  update_connection_views();
}

void WalletWindow::build_ui() {
  setWindowTitle("SelfCoin Reference Wallet");
  resize(980, 720);

  auto* central = new QWidget(this);
  auto* root = new QVBoxLayout(central);

  auto* top_actions = new QHBoxLayout();
  auto* create_button = new QPushButton("Create Wallet", this);
  auto* open_button = new QPushButton("Open Wallet", this);
  auto* import_button = new QPushButton("Import Wallet", this);
  auto* export_button = new QPushButton("Export Backup", this);
  auto* refresh_button = new QPushButton("Refresh", this);
  top_actions->addWidget(create_button);
  top_actions->addWidget(open_button);
  top_actions->addWidget(import_button);
  top_actions->addWidget(export_button);
  top_actions->addWidget(refresh_button);
  top_actions->addStretch(1);
  root->addLayout(top_actions);

  tabs_ = new QTabWidget(this);
  root->addWidget(tabs_);

  auto* home = new QWidget(this);
  auto* home_layout = new QVBoxLayout(home);
  auto* summary_box = new QGroupBox("Wallet", home);
  auto* summary_grid = new QGridLayout(summary_box);
  summary_grid->addWidget(new QLabel("Status:", summary_box), 0, 0);
  wallet_status_label_ = new QLabel("No wallet loaded", summary_box);
  summary_grid->addWidget(wallet_status_label_, 0, 1);
  summary_grid->addWidget(new QLabel("Wallet file:", summary_box), 1, 0);
  wallet_file_label_ = new QLabel("-", summary_box);
  wallet_file_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  summary_grid->addWidget(wallet_file_label_, 1, 1);
  summary_grid->addWidget(new QLabel("Network:", summary_box), 2, 0);
  network_label_ = new QLabel("mainnet", summary_box);
  summary_grid->addWidget(network_label_, 2, 1);
  summary_grid->addWidget(new QLabel("Available balance:", summary_box), 3, 0);
  balance_label_ = new QLabel("0 SC", summary_box);
  summary_grid->addWidget(balance_label_, 3, 1);
  summary_grid->addWidget(new QLabel("Pending outgoing:", summary_box), 4, 0);
  pending_balance_label_ = new QLabel("0 SC", summary_box);
  summary_grid->addWidget(pending_balance_label_, 4, 1);
  summary_grid->addWidget(new QLabel("Receive address:", summary_box), 5, 0);
  receive_address_home_label_ = new QLabel("-", summary_box);
  receive_address_home_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  summary_grid->addWidget(receive_address_home_label_, 5, 1);
  summary_grid->addWidget(new QLabel("Synced tip:", summary_box), 6, 0);
  tip_status_label_ = new QLabel("-", summary_box);
  summary_grid->addWidget(tip_status_label_, 6, 1);
  home_layout->addWidget(summary_box);

  auto* home_connection_box = new QGroupBox("Connections", home);
  auto* home_connection_layout = new QVBoxLayout(home_connection_box);
  connection_summary_label_ = new QLabel(home_connection_box);
  connection_summary_label_->setWordWrap(true);
  home_connection_layout->addWidget(connection_summary_label_);
  home_layout->addWidget(home_connection_box);

  auto* home_note = new QLabel(
      "This first wallet keeps the scope narrow: wallet file management, receive address, connection settings, and a disciplined UI shell for send/history/mint flows.",
      home);
  home_note->setWordWrap(true);
  home_layout->addWidget(home_note);
  home_layout->addStretch(1);
  tabs_->addTab(home, "Home");

  auto* receive = new QWidget(this);
  auto* receive_layout = new QVBoxLayout(receive);
  auto* receive_box = new QGroupBox("Receive", receive);
  auto* receive_box_layout = new QVBoxLayout(receive_box);
  receive_address_label_ = new QLabel("-", receive_box);
  receive_address_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  receive_address_label_->setWordWrap(true);
  auto* copy_address_button = new QPushButton("Copy Address", receive_box);
  receive_box_layout->addWidget(new QLabel("Share this address to receive SelfCoin on-chain.", receive_box));
  receive_box_layout->addWidget(receive_address_label_);
  receive_box_layout->addWidget(copy_address_button);
  receive_layout->addWidget(receive_box);
  receive_layout->addStretch(1);
  tabs_->addTab(receive, "Receive");

  auto* send = new QWidget(this);
  auto* send_layout = new QVBoxLayout(send);
  auto* send_form_box = new QGroupBox("Send On-Chain", send);
  auto* send_form = new QFormLayout(send_form_box);
  send_address_edit_ = new QLineEdit(send_form_box);
  send_amount_edit_ = new QLineEdit(send_form_box);
  send_fee_edit_ = new QLineEdit(send_form_box);
  send_fee_edit_->setText("0.001");
  send_form->addRow("Destination address", send_address_edit_);
  send_form->addRow("Amount (SC)", send_amount_edit_);
  send_form->addRow("Fee (SC)", send_fee_edit_);
  auto* send_actions = new QHBoxLayout();
  auto* send_review_button = new QPushButton("Review Send", send_form_box);
  auto* send_button = new QPushButton("Send", send_form_box);
  send_actions->addWidget(send_review_button);
  send_actions->addWidget(send_button);
  send_form->addRow("", send_actions);
  send_layout->addWidget(send_form_box);
  auto* send_note = new QLabel(
      "The reference wallet validates inputs here. Transaction building and broadcast should be wired against lightserver in the next wallet phase, not hidden behind a fake send button.",
      send);
  send_note->setWordWrap(true);
  send_layout->addWidget(send_note);
  send_layout->addStretch(1);
  tabs_->addTab(send, "Send");

  auto* history = new QWidget(this);
  auto* history_layout = new QVBoxLayout(history);
  history_view_ = new QPlainTextEdit(history);
  history_view_->setReadOnly(true);
  history_view_->setPlainText("No wallet history yet.\nOpen or create a wallet to start recording local wallet actions.");
  history_layout->addWidget(history_view_);
  tabs_->addTab(history, "History");

  auto* mint = new QWidget(this);
  auto* mint_layout = new QVBoxLayout(mint);
  auto* mint_deposit_box = new QGroupBox("Mint Deposit", mint);
  auto* mint_deposit_form = new QFormLayout(mint_deposit_box);
  mint_deposit_amount_edit_ = new QLineEdit(mint_deposit_box);
  auto* mint_deposit_button = new QPushButton("Prepare Deposit", mint_deposit_box);
  mint_deposit_form->addRow("Amount (SC)", mint_deposit_amount_edit_);
  mint_deposit_form->addRow("", mint_deposit_button);
  mint_layout->addWidget(mint_deposit_box);

  auto* mint_redeem_box = new QGroupBox("Redeem From Mint", mint);
  auto* mint_redeem_form = new QFormLayout(mint_redeem_box);
  mint_redeem_amount_edit_ = new QLineEdit(mint_redeem_box);
  mint_redeem_address_edit_ = new QLineEdit(mint_redeem_box);
  auto* mint_redeem_button = new QPushButton("Prepare Redemption", mint_redeem_box);
  mint_redeem_form->addRow("Amount (SC)", mint_redeem_amount_edit_);
  mint_redeem_form->addRow("Destination address", mint_redeem_address_edit_);
  mint_redeem_form->addRow("", mint_redeem_button);
  mint_layout->addWidget(mint_redeem_box);

  mint_status_label_ = new QLabel("Mint URL not configured yet.", mint);
  mint_status_label_->setWordWrap(true);
  mint_layout->addWidget(mint_status_label_);
  mint_layout->addStretch(1);
  tabs_->addTab(mint, "Mint");

  auto* settings = new QWidget(this);
  auto* settings_layout = new QVBoxLayout(settings);
  auto* settings_box = new QGroupBox("Connections", settings);
  auto* settings_form = new QFormLayout(settings_box);
  lightserver_url_edit_ = new QLineEdit(settings_box);
  mint_url_edit_ = new QLineEdit(settings_box);
  settings_form->addRow("Lightserver URL", lightserver_url_edit_);
  settings_form->addRow("Mint URL", mint_url_edit_);
  auto* save_settings_button = new QPushButton("Save Settings", settings_box);
  settings_form->addRow("", save_settings_button);
  settings_layout->addWidget(settings_box);

  auto* settings_note = new QLabel(
      "The reference wallet deliberately keeps one wallet, one lightserver, and one mint endpoint at a time. Settings are stored locally with QSettings.",
      settings);
  settings_note->setWordWrap(true);
  settings_layout->addWidget(settings_note);
  settings_layout->addStretch(1);
  tabs_->addTab(settings, "Settings");

  setCentralWidget(central);

  connect(create_button, &QPushButton::clicked, this, [this]() { create_wallet(); });
  connect(open_button, &QPushButton::clicked, this, [this]() { open_wallet(); });
  connect(import_button, &QPushButton::clicked, this, [this]() { import_wallet(); });
  connect(export_button, &QPushButton::clicked, this, [this]() { export_wallet_secret(); });
  connect(refresh_button, &QPushButton::clicked, this, [this]() { refresh_chain_state(true); });
  connect(copy_address_button, &QPushButton::clicked, this, [this]() {
    if (!wallet_) return;
    QApplication::clipboard()->setText(QString::fromStdString(wallet_->address));
    statusBar()->showMessage("Receive address copied to clipboard.", 3000);
  });
  connect(send_review_button, &QPushButton::clicked, this, [this]() { validate_send_form(); });
  connect(send_button, &QPushButton::clicked, this, [this]() { submit_send(); });
  connect(mint_deposit_button, &QPushButton::clicked, this, [this]() { show_mint_info("deposit"); });
  connect(mint_redeem_button, &QPushButton::clicked, this, [this]() { show_mint_info("redemption"); });
  connect(save_settings_button, &QPushButton::clicked, this, [this]() { save_connection_settings(); });
}

void WalletWindow::load_settings() {
  QSettings settings(kSettingsOrg, kSettingsApp);
  lightserver_url_edit_->setText(settings.value("lightserver_url", "http://127.0.0.1:8080").toString());
  mint_url_edit_->setText(settings.value("mint_url", "http://127.0.0.1:8090").toString());
}

void WalletWindow::save_settings() const {
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.setValue("lightserver_url", lightserver_url_edit_->text().trimmed());
  settings.setValue("mint_url", mint_url_edit_->text().trimmed());
}

void WalletWindow::update_wallet_views() {
  if (!wallet_) {
    wallet_status_label_->setText("No wallet loaded");
    wallet_file_label_->setText("-");
    network_label_->setText("mainnet");
    receive_address_home_label_->setText("-");
    receive_address_label_->setText("-");
    balance_label_->setText("0 SC");
    pending_balance_label_->setText("0 SC");
    tip_status_label_->setText("-");
    return;
  }
  wallet_status_label_->setText("Wallet loaded");
  wallet_file_label_->setText(QString::fromStdString(wallet_->file_path));
  network_label_->setText(QString::fromStdString(wallet_->network_name));
  receive_address_home_label_->setText(QString::fromStdString(wallet_->address));
  receive_address_label_->setText(QString::fromStdString(wallet_->address));
  std::uint64_t total = 0;
  for (const auto& utxo : utxos_) total += utxo.value;
  balance_label_->setText(format_coin_amount(total));
  pending_balance_label_->setText("0 SC");
  tip_status_label_->setText(tip_height_ == 0 ? "-" : QString("height %1").arg(tip_height_));
}

void WalletWindow::update_connection_views() {
  const QString lightserver = lightserver_url_edit_->text().trimmed();
  const QString mint = mint_url_edit_->text().trimmed();
  connection_summary_label_->setText(
      QString("Lightserver: %1\nMint: %2")
          .arg(lightserver.isEmpty() ? "not configured" : lightserver)
          .arg(mint.isEmpty() ? "not configured" : mint));
  mint_status_label_->setText(mint.isEmpty() ? "Mint URL not configured yet." : "Mint endpoint configured: " + mint);
}

void WalletWindow::render_history_view() {
  if (history_lines_.empty()) {
    history_view_->setPlainText("No wallet history yet.\nOpen or create a wallet to start syncing activity.");
    return;
  }
  history_view_->setPlainText(history_lines_.join("\n"));
}

void WalletWindow::save_wallet_local_state() const {
  if (!wallet_) return;
  QSettings settings(kSettingsOrg, kSettingsApp);
  QStringList txids;
  for (const auto& txid : local_sent_txids_) txids.push_back(QString::fromStdString(txid));
  settings.setValue(QString("wallet_state/%1/local_sent_txids").arg(QString::fromStdString(wallet_->file_path)), txids);
}

void WalletWindow::load_wallet_local_state() {
  local_sent_txids_.clear();
  if (!wallet_) return;
  QSettings settings(kSettingsOrg, kSettingsApp);
  const auto raw = settings.value(QString("wallet_state/%1/local_sent_txids").arg(QString::fromStdString(wallet_->file_path)))
                       .toStringList();
  for (const auto& txid : raw) local_sent_txids_.push_back(txid.toStdString());
}

void WalletWindow::refresh_chain_state(bool interactive) {
  if (!wallet_) return;
  const QString rpc_url = lightserver_url_edit_->text().trimmed();
  if (rpc_url.isEmpty()) {
    if (interactive) QMessageBox::warning(this, "Refresh", "Configure a lightserver URL first.");
    return;
  }
  const Hash32 scripthash = wallet_scripthash_from_address(wallet_->address);
  if (scripthash == zero_hash()) {
    if (interactive) QMessageBox::warning(this, "Refresh", "Wallet address is invalid.");
    return;
  }

  std::string err;
  auto status = lightserver::rpc_get_status(rpc_url.toStdString(), &err);
  if (!status) {
    if (interactive) QMessageBox::warning(this, "Refresh", QString::fromStdString(err));
    return;
  }
  auto utxos = lightserver::rpc_get_utxos(rpc_url.toStdString(), scripthash, &err);
  if (!utxos) {
    if (interactive) QMessageBox::warning(this, "Refresh", QString::fromStdString(err));
    return;
  }
  auto history = lightserver::rpc_get_history(rpc_url.toStdString(), scripthash, &err);
  if (!history) {
    if (interactive) QMessageBox::warning(this, "Refresh", QString::fromStdString(err));
    return;
  }

  tip_height_ = status->tip_height;
  utxos_.clear();
  for (const auto& utxo : *utxos) {
    utxos_.push_back(WalletUtxo{
        .txid_hex = hex_encode32(utxo.txid),
        .vout = utxo.vout,
        .value = utxo.value,
        .height = utxo.height,
        .script_pubkey = utxo.script_pubkey,
    });
  }

  std::set<std::string> sent_index(local_sent_txids_.begin(), local_sent_txids_.end());
  history_lines_.clear();
  const auto own_decoded = selfcoin::address::decode(wallet_->address);
  const Bytes own_spk = own_decoded ? selfcoin::address::p2pkh_script_pubkey(own_decoded->pubkey_hash) : Bytes{};
  std::reverse(history->begin(), history->end());
  for (const auto& entry : *history) {
    const std::string txid_hex = hex_encode32(entry.txid);
    auto txv = lightserver::rpc_get_tx(rpc_url.toStdString(), entry.txid, &err);
    if (!txv) continue;
    auto tx = Tx::parse(txv->tx_bytes);
    if (!tx) continue;
    std::uint64_t credited = 0;
    for (const auto& out : tx->outputs) {
      if (out.script_pubkey == own_spk) {
        credited += out.value;
      }
    }
    QString kind = sent_index.count(txid_hex) ? "sent" : (credited > 0 ? "received" : "activity");
    QString detail = credited > 0 ? format_coin_amount(credited) : QString("tx %1").arg(elide_middle(QString::fromStdString(txid_hex), 10));
    history_lines_.push_back(QString("[%1] height=%2 %3 %4")
                                 .arg(kind)
                                 .arg(entry.height)
                                 .arg(detail)
                                 .arg(elide_middle(QString::fromStdString(txid_hex), 12)));
  }

  update_wallet_views();
  render_history_view();
  update_connection_views();
  if (interactive) statusBar()->showMessage("Wallet state refreshed from lightserver.", 3000);
}

std::optional<WalletWindow::LoadedWallet> WalletWindow::load_wallet_file(const QString& path, const QString& passphrase) {
  selfcoin::keystore::ValidatorKey key;
  std::string err;
  if (!selfcoin::keystore::load_validator_keystore(path.toStdString(), passphrase.toStdString(), &key, &err)) {
    QMessageBox::warning(this, "Open Wallet", QString::fromStdString(err));
    return std::nullopt;
  }

  LoadedWallet loaded;
  loaded.file_path = path.toStdString();
  loaded.passphrase = passphrase.toStdString();
  loaded.network_name = key.network_name;
  loaded.address = key.address;
  loaded.pubkey_hex = selfcoin::hex_encode(selfcoin::Bytes(key.pubkey.begin(), key.pubkey.end()));
  return loaded;
}

std::optional<QString> WalletWindow::prompt_passphrase(const QString& title, bool confirm) const {
  bool ok = false;
  const QString pass = QInputDialog::getText(const_cast<WalletWindow*>(this), title, "Passphrase",
                                             QLineEdit::Password, "", &ok);
  if (!ok) return std::nullopt;
  if (!confirm) return pass;
  const QString confirm_pass = QInputDialog::getText(const_cast<WalletWindow*>(this), title, "Confirm passphrase",
                                                     QLineEdit::Password, "", &ok);
  if (!ok) return std::nullopt;
  if (pass != confirm_pass) {
    QMessageBox::warning(const_cast<WalletWindow*>(this), title, "Passphrases do not match.");
    return std::nullopt;
  }
  return pass;
}

bool WalletWindow::ensure_wallet_loaded(const QString& action_name) {
  if (wallet_) return true;
  QMessageBox::information(this, action_name, "Open, create, or import a wallet first.");
  return false;
}

std::optional<selfcoin::keystore::ValidatorKey> WalletWindow::load_wallet_key(std::string* err) const {
  if (!wallet_) {
    if (err) *err = "wallet not loaded";
    return std::nullopt;
  }
  selfcoin::keystore::ValidatorKey key;
  if (!selfcoin::keystore::load_validator_keystore(wallet_->file_path, wallet_->passphrase, &key, err)) return std::nullopt;
  return key;
}

void WalletWindow::create_wallet() {
  const QString path = QFileDialog::getSaveFileName(this, "Create Wallet", QDir::homePath() + "/selfcoin-wallet.json",
                                                    "Wallet files (*.json)");
  if (path.isEmpty()) return;
  const auto passphrase = prompt_passphrase("Create Wallet", true);
  if (!passphrase.has_value()) return;

  selfcoin::keystore::ValidatorKey key;
  std::string err;
  if (!selfcoin::keystore::create_validator_keystore(path.toStdString(), passphrase->toStdString(), "mainnet",
                                                      selfcoin::keystore::hrp_for_network("mainnet"), std::nullopt, &key,
                                                      &err)) {
    QMessageBox::warning(this, "Create Wallet", QString::fromStdString(err));
    return;
  }

  LoadedWallet loaded;
  loaded.file_path = path.toStdString();
  loaded.passphrase = passphrase->toStdString();
  loaded.network_name = key.network_name;
  loaded.address = key.address;
  loaded.pubkey_hex = selfcoin::hex_encode(selfcoin::Bytes(key.pubkey.begin(), key.pubkey.end()));
  wallet_ = loaded;
  load_wallet_local_state();
  update_wallet_views();
  history_lines_.push_back("Created wallet at " + path);
  render_history_view();
  refresh_chain_state(false);
  statusBar()->showMessage("Wallet created.", 3000);
}

void WalletWindow::open_wallet() {
  const QString path = QFileDialog::getOpenFileName(this, "Open Wallet", QDir::homePath(), "Wallet files (*.json)");
  if (path.isEmpty()) return;
  const auto passphrase = prompt_passphrase("Open Wallet", false);
  if (!passphrase.has_value()) return;
  auto loaded = load_wallet_file(path, *passphrase);
  if (!loaded) return;
  wallet_ = *loaded;
  load_wallet_local_state();
  update_wallet_views();
  history_lines_.push_back("Opened wallet " + path);
  render_history_view();
  refresh_chain_state(false);
  statusBar()->showMessage("Wallet opened.", 3000);
}

void WalletWindow::import_wallet() {
  const QString path = QFileDialog::getSaveFileName(this, "Import Wallet", QDir::homePath() + "/selfcoin-wallet.json",
                                                    "Wallet files (*.json)");
  if (path.isEmpty()) return;
  bool ok = false;
  const QString privkey_hex = QInputDialog::getText(this, "Import Wallet", "Private key (32-byte hex)",
                                                    QLineEdit::Normal, "", &ok);
  if (!ok || privkey_hex.trimmed().isEmpty()) return;
  auto seed = decode_hex32_string(privkey_hex.trimmed().toStdString());
  if (!seed) {
    QMessageBox::warning(this, "Import Wallet", "Private key must be exactly 32 bytes in hex.");
    return;
  }
  const auto passphrase = prompt_passphrase("Import Wallet", true);
  if (!passphrase.has_value()) return;

  selfcoin::keystore::ValidatorKey key;
  std::string err;
  if (!selfcoin::keystore::create_validator_keystore(path.toStdString(), passphrase->toStdString(), "mainnet",
                                                      selfcoin::keystore::hrp_for_network("mainnet"), *seed, &key, &err)) {
    QMessageBox::warning(this, "Import Wallet", QString::fromStdString(err));
    return;
  }

  LoadedWallet loaded;
  loaded.file_path = path.toStdString();
  loaded.passphrase = passphrase->toStdString();
  loaded.network_name = key.network_name;
  loaded.address = key.address;
  loaded.pubkey_hex = selfcoin::hex_encode(selfcoin::Bytes(key.pubkey.begin(), key.pubkey.end()));
  wallet_ = loaded;
  load_wallet_local_state();
  update_wallet_views();
  history_lines_.push_back("Imported wallet into " + path);
  render_history_view();
  refresh_chain_state(false);
  statusBar()->showMessage("Wallet imported.", 3000);
}

void WalletWindow::export_wallet_secret() {
  if (!ensure_wallet_loaded("Export Backup")) return;

  selfcoin::keystore::ValidatorKey key;
  std::string err;
  if (!selfcoin::keystore::load_validator_keystore(wallet_->file_path, wallet_->passphrase, &key, &err)) {
    QMessageBox::warning(this, "Export Backup", QString::fromStdString(err));
    return;
  }

  const QString privkey_hex = QString::fromStdString(selfcoin::hex_encode(selfcoin::Bytes(key.privkey.begin(), key.privkey.end())));
  QMessageBox::information(
      this, "Export Backup",
      "Store this private key offline.\n\nPrivate key:\n" + privkey_hex +
          "\n\nThis reference wallet does not show it during normal use unless you explicitly export it.");
  history_lines_.push_back("Exported backup material for " + QString::fromStdString(wallet_->file_path));
  render_history_view();
}

void WalletWindow::save_connection_settings() {
  save_settings();
  update_connection_views();
  history_lines_.push_back("Saved local connection settings.");
  render_history_view();
  refresh_chain_state(false);
  statusBar()->showMessage("Settings saved.", 3000);
}

void WalletWindow::validate_send_form() {
  if (!ensure_wallet_loaded("Review Send")) return;
  const QString address = send_address_edit_->text().trimmed();
  const QString amount = send_amount_edit_->text().trimmed();
  const QString fee = send_fee_edit_->text().trimmed();
  if (address.isEmpty() || amount.isEmpty() || fee.isEmpty()) {
    QMessageBox::warning(this, "Review Send", "Destination address, amount, and fee are required.");
    return;
  }
  if (!selfcoin::address::decode(address.toStdString()).has_value()) {
    QMessageBox::warning(this, "Review Send", "Destination address is invalid.");
    return;
  }
  bool amount_ok = false;
  bool fee_ok = false;
  const double amount_value = amount.toDouble(&amount_ok);
  const double fee_value = fee.toDouble(&fee_ok);
  if (!amount_ok || amount_value <= 0.0 || !fee_ok || fee_value < 0.0) {
    QMessageBox::warning(this, "Review Send", "Amount must be positive and fee must be zero or positive.");
    return;
  }

  auto amount_units = parse_coin_amount(amount);
  auto fee_units = parse_coin_amount(fee);
  if (!amount_units || !fee_units) {
    QMessageBox::warning(this, "Review Send", "Amount and fee must be valid coin values with up to 8 decimals.");
    return;
  }
  std::uint64_t total = 0;
  for (const auto& utxo : utxos_) total += utxo.value;
  if (total < *amount_units + *fee_units) {
    QMessageBox::warning(this, "Review Send", "Insufficient on-chain wallet balance.");
    return;
  }

  QMessageBox::information(
      this, "Review Send",
      QString("Destination: %1\nAmount: %2\nFee: %3\nTotal spend: %4")
          .arg(elide_middle(address))
          .arg(format_coin_amount(*amount_units))
          .arg(format_coin_amount(*fee_units))
          .arg(format_coin_amount(*amount_units + *fee_units)));
}

void WalletWindow::submit_send() {
  if (!ensure_wallet_loaded("Send")) return;
  const QString rpc_url = lightserver_url_edit_->text().trimmed();
  if (rpc_url.isEmpty()) {
    QMessageBox::warning(this, "Send", "Configure a lightserver URL first.");
    return;
  }

  const QString destination = send_address_edit_->text().trimmed();
  auto decoded_to = selfcoin::address::decode(destination.toStdString());
  if (!decoded_to) {
    QMessageBox::warning(this, "Send", "Destination address is invalid.");
    return;
  }
  auto amount_units = parse_coin_amount(send_amount_edit_->text());
  auto fee_units = parse_coin_amount(send_fee_edit_->text());
  if (!amount_units || !fee_units || *amount_units == 0) {
    QMessageBox::warning(this, "Send", "Amount must be positive and fee must be valid.");
    return;
  }
  if (utxos_.empty()) refresh_chain_state(false);
  std::vector<std::pair<OutPoint, TxOut>> prevs;
  std::uint64_t selected = 0;
  for (const auto& utxo : utxos_) {
    auto txid = decode_hex32_string(utxo.txid_hex);
    if (!txid) continue;
    prevs.push_back({OutPoint{*txid, utxo.vout}, TxOut{utxo.value, utxo.script_pubkey}});
    selected += utxo.value;
    if (selected >= *amount_units + *fee_units) break;
  }
  if (selected < *amount_units + *fee_units) {
    QMessageBox::warning(this, "Send", "Insufficient confirmed UTXOs.");
    return;
  }
  std::string err;
  auto key = load_wallet_key(&err);
  if (!key) {
    QMessageBox::warning(this, "Send", QString::fromStdString(err));
    return;
  }

  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{*amount_units, selfcoin::address::p2pkh_script_pubkey(decoded_to->pubkey_hash)});
  const std::uint64_t change = selected - *amount_units - *fee_units;
  auto own_decoded = selfcoin::address::decode(wallet_->address);
  if (!own_decoded) {
    QMessageBox::warning(this, "Send", "Wallet address is invalid.");
    return;
  }
  if (change > 0) outputs.push_back(TxOut{change, selfcoin::address::p2pkh_script_pubkey(own_decoded->pubkey_hash)});

  auto tx = selfcoin::build_signed_p2pkh_tx_multi_input(
      prevs, selfcoin::Bytes(key->privkey.begin(), key->privkey.end()), outputs, &err);
  if (!tx) {
    QMessageBox::warning(this, "Send", QString::fromStdString(err));
    return;
  }

  auto result = lightserver::rpc_broadcast_tx(rpc_url.toStdString(), tx->serialize(), &err);
  if (!result) {
    QMessageBox::warning(this, "Send", QString::fromStdString(err));
    return;
  }
  if (!result->accepted) {
    QMessageBox::warning(this, "Send", QString("Broadcast rejected: %1").arg(QString::fromStdString(result->error)));
    return;
  }

  local_sent_txids_.push_back(result->txid_hex);
  save_wallet_local_state();
  history_lines_.push_back(QString("[pending] sent %1 -> %2 (%3)")
                               .arg(format_coin_amount(*amount_units))
                               .arg(elide_middle(destination))
                               .arg(elide_middle(QString::fromStdString(result->txid_hex), 12)));
  render_history_view();
  refresh_chain_state(false);
  statusBar()->showMessage("Transaction broadcasted.", 3000);
}

void WalletWindow::show_mint_info(const QString& action_name) {
  if (!ensure_wallet_loaded("Mint")) return;
  if (mint_url_edit_->text().trimmed().isEmpty()) {
    QMessageBox::warning(this, "Mint", "Configure a mint URL first.");
    return;
  }

  if (action_name == "deposit") {
    if (mint_deposit_amount_edit_->text().trimmed().isEmpty()) {
      QMessageBox::warning(this, "Mint Deposit", "Enter a deposit amount.");
      return;
    }
    QMessageBox::information(
        this, "Mint Deposit",
        QString("Mint deposit preparation is scoped for the next wallet phase.\n\nAmount: %1 SC\nWallet: %2\nMint: %3")
            .arg(mint_deposit_amount_edit_->text().trimmed())
            .arg(QString::fromStdString(wallet_->address))
            .arg(mint_url_edit_->text().trimmed()));
    history_lines_.push_back("Prepared mint deposit intent for " + mint_deposit_amount_edit_->text().trimmed() + " SC");
    render_history_view();
    return;
  }

  if (mint_redeem_amount_edit_->text().trimmed().isEmpty() || mint_redeem_address_edit_->text().trimmed().isEmpty()) {
    QMessageBox::warning(this, "Mint Redemption", "Enter amount and destination address.");
    return;
  }
  if (!selfcoin::address::decode(mint_redeem_address_edit_->text().trimmed().toStdString()).has_value()) {
    QMessageBox::warning(this, "Mint Redemption", "Destination address is invalid.");
    return;
  }
  QMessageBox::information(
      this, "Mint Redemption",
      QString("Mint redemption preparation is scoped for the next wallet phase.\n\nAmount: %1 SC\nDestination: %2\nMint: %3")
          .arg(mint_redeem_amount_edit_->text().trimmed())
          .arg(elide_middle(mint_redeem_address_edit_->text().trimmed()))
          .arg(mint_url_edit_->text().trimmed()));
  history_lines_.push_back("Prepared mint redemption intent for " + mint_redeem_amount_edit_->text().trimmed() + " SC");
  render_history_view();
}

}  // namespace selfcoin::wallet
