#include "wallet_window.hpp"

#include <array>
#include <algorithm>
#include <map>
#include <random>
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
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QTabWidget>
#include <QFontDatabase>
#include <QVBoxLayout>
#include <QWidget>

#include "address/address.hpp"
#include "common/types.hpp"
#include "consensus/monetary.hpp"
#include "crypto/hash.hpp"
#include "keystore/validator_keystore.hpp"
#include "lightserver/client.hpp"
#include "privacy/mint_client.hpp"
#include "privacy/mint_scripts.hpp"
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

QString mint_endpoint(const QString& base_url, const QString& path) {
  QString out = base_url.trimmed();
  while (out.endsWith('/')) out.chop(1);
  return out + path;
}

QString random_hex_string(std::size_t bytes_len) {
  std::random_device rd;
  Bytes b(bytes_len, 0);
  for (auto& v : b) v = static_cast<std::uint8_t>(rd());
  return QString::fromStdString(hex_encode(b));
}

std::vector<std::uint64_t> split_into_denominations(std::uint64_t amount) {
  std::vector<std::uint64_t> out;
  if (amount == 0) return out;
  std::vector<std::uint64_t> denoms;
  for (std::uint64_t scale = 1; scale <= amount; ) {
    denoms.push_back(scale);
    if (scale <= amount / 2) denoms.push_back(scale * 2);
    if (scale <= amount / 5) denoms.push_back(scale * 5);
    if (scale > amount / 10) break;
    scale *= 10;
  }
  std::sort(denoms.begin(), denoms.end());
  denoms.erase(std::unique(denoms.begin(), denoms.end()), denoms.end());
  std::sort(denoms.rbegin(), denoms.rend());
  std::uint64_t remaining = amount;
  for (const auto denom : denoms) {
    while (denom <= remaining) {
      out.push_back(denom);
      remaining -= denom;
    }
  }
  if (remaining > 0) out.push_back(remaining);
  return out;
}

QString mono_font_family() {
  QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  return f.family();
}

QString trim_after_token(const QString& line, const QString& token) {
  const int pos = line.indexOf(token);
  if (pos < 0) return {};
  return line.mid(pos + token.size()).trimmed();
}

QString extract_field_value(const QString& line, const QString& field) {
  const QString needle = field + "=";
  const int pos = line.indexOf(needle);
  if (pos < 0) return {};
  int end = line.indexOf(' ', pos + needle.size());
  if (end < 0) end = line.size();
  return line.mid(pos + needle.size(), end - (pos + needle.size())).trimmed();
}

QString badge_text(const QString& status) {
  const QString upper = status.trimmed().toUpper();
  return upper.isEmpty() ? "[INFO]" : "[" + upper + "]";
}

QString mint_state_badge(const QString& state) {
  const QString lower = state.trimmed().toLower();
  if (lower == "finalized" || lower == "issued") return "FINALIZED";
  if (lower == "broadcast" || lower == "pending" || lower == "registered") return "PENDING";
  if (lower == "rejected" || lower == "failed") return "FAILED";
  return state.trimmed().isEmpty() ? "INFO" : state.trimmed().toUpper();
}

std::optional<std::vector<std::size_t>> choose_note_subset_exact(const std::vector<selfcoin::wallet::WalletWindow::MintNote>& notes,
                                                                 std::uint64_t target) {
  std::map<std::uint64_t, std::vector<std::size_t>> reachable;
  reachable[0] = {};
  for (std::size_t i = 0; i < notes.size(); ++i) {
    std::vector<std::pair<std::uint64_t, std::vector<std::size_t>>> additions;
    for (const auto& [sum, indexes] : reachable) {
      if (sum + notes[i].amount > target) continue;
      if (reachable.find(sum + notes[i].amount) != reachable.end()) continue;
      auto next = indexes;
      next.push_back(i);
      additions.push_back({sum + notes[i].amount, std::move(next)});
    }
    for (auto& [sum, indexes] : additions) reachable.emplace(sum, std::move(indexes));
    auto it = reachable.find(target);
    if (it != reachable.end()) return it->second;
  }
  return std::nullopt;
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
      "Transactions are signed locally and broadcast through lightserver. Use Review Send before final submission.",
      send);
  send_note->setWordWrap(true);
  send_layout->addWidget(send_note);
  send_layout->addStretch(1);
  tabs_->addTab(send, "Send");

  auto* history = new QWidget(this);
  auto* history_layout = new QVBoxLayout(history);
  auto* history_actions = new QHBoxLayout();
  history_detail_button_ = new QPushButton("Selected Transaction Details", history);
  history_actions->addStretch(1);
  history_actions->addWidget(history_detail_button_);
  history_layout->addLayout(history_actions);
  history_view_ = new QListWidget(history);
  history_layout->addWidget(history_view_);
  tabs_->addTab(history, "History");

  auto* mint = new QWidget(this);
  auto* mint_layout = new QVBoxLayout(mint);

  auto* mint_summary_box = new QGroupBox("Mint Summary", mint);
  auto* mint_summary_grid = new QGridLayout(mint_summary_box);
  mint_summary_grid->addWidget(new QLabel("Current deposit ref:", mint_summary_box), 0, 0);
  mint_deposit_ref_label_ = new QLabel("-", mint_summary_box);
  mint_deposit_ref_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  mint_summary_grid->addWidget(mint_deposit_ref_label_, 0, 1);
  mint_summary_grid->addWidget(new QLabel("Last redemption batch:", mint_summary_box), 1, 0);
  mint_redemption_label_ = new QLabel("-", mint_summary_box);
  mint_redemption_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  mint_summary_grid->addWidget(mint_redemption_label_, 1, 1);
  mint_summary_grid->addWidget(new QLabel("Private balance:", mint_summary_box), 2, 0);
  mint_private_balance_label_ = new QLabel("0 SC", mint_summary_box);
  mint_summary_grid->addWidget(mint_private_balance_label_, 2, 1);
  mint_summary_grid->addWidget(new QLabel("Active notes:", mint_summary_box), 3, 0);
  mint_note_count_label_ = new QLabel("0", mint_summary_box);
  mint_summary_grid->addWidget(mint_note_count_label_, 3, 1);
  mint_status_label_ = new QLabel("Mint URL not configured yet.", mint_summary_box);
  mint_status_label_->setWordWrap(true);
  mint_summary_grid->addWidget(mint_status_label_, 4, 0, 1, 2);
  mint_layout->addWidget(mint_summary_box);

  auto* mint_ops = new QWidget(mint);
  auto* mint_ops_layout = new QHBoxLayout(mint_ops);
  mint_ops_layout->setContentsMargins(0, 0, 0, 0);

  auto* mint_left = new QVBoxLayout();
  auto* mint_right = new QVBoxLayout();

  auto* mint_deposit_box = new QGroupBox("Deposit To Mint", mint_ops);
  auto* mint_deposit_form = new QFormLayout(mint_deposit_box);
  mint_deposit_amount_edit_ = new QLineEdit(mint_deposit_box);
  auto* mint_deposit_button = new QPushButton("Deposit To Mint", mint_deposit_box);
  mint_deposit_form->addRow("Amount (SC)", mint_deposit_amount_edit_);
  mint_deposit_form->addRow("", mint_deposit_button);
  mint_left->addWidget(mint_deposit_box);

  auto* mint_issue_box = new QGroupBox("Issue Private Notes", mint_ops);
  auto* mint_issue_form = new QFormLayout(mint_issue_box);
  mint_issue_amount_edit_ = new QLineEdit(mint_issue_box);
  auto* mint_issue_button = new QPushButton("Issue Notes", mint_issue_box);
  mint_notes_label_ = new QLabel("-", mint_issue_box);
  mint_notes_label_->setWordWrap(true);
  mint_notes_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  mint_issue_form->addRow("Issue amount (SC)", mint_issue_amount_edit_);
  mint_issue_form->addRow("Note mix", mint_notes_label_);
  mint_issue_form->addRow("", mint_issue_button);
  mint_left->addWidget(mint_issue_box);

  auto* mint_redeem_box = new QGroupBox("Redeem To Wallet", mint_ops);
  auto* mint_redeem_form = new QFormLayout(mint_redeem_box);
  mint_redeem_amount_edit_ = new QLineEdit(mint_redeem_box);
  mint_redeem_address_edit_ = new QLineEdit(mint_redeem_box);
  auto* mint_redeem_actions = new QHBoxLayout();
  auto* mint_redeem_button = new QPushButton("Redeem", mint_redeem_box);
  auto* mint_redeem_status_button = new QPushButton("Refresh Redemption", mint_redeem_box);
  mint_redeem_actions->addWidget(mint_redeem_button);
  mint_redeem_actions->addWidget(mint_redeem_status_button);
  mint_redeem_form->addRow("Amount (SC)", mint_redeem_amount_edit_);
  mint_redeem_form->addRow("Destination address", mint_redeem_address_edit_);
  mint_redeem_form->addRow("", mint_redeem_actions);
  mint_left->addWidget(mint_redeem_box);
  mint_left->addStretch(1);

  auto* deposits_box = new QGroupBox("Recent Deposits", mint_ops);
  auto* deposits_layout = new QVBoxLayout(deposits_box);
  mint_deposits_view_ = new QListWidget(deposits_box);
  deposits_layout->addWidget(mint_deposits_view_);
  mint_right->addWidget(deposits_box);

  auto* notes_box = new QGroupBox("Note Inventory", mint_ops);
  auto* notes_layout = new QVBoxLayout(notes_box);
  mint_notes_view_ = new QListWidget(notes_box);
  notes_layout->addWidget(mint_notes_view_);
  mint_right->addWidget(notes_box);

  auto* redemption_box = new QGroupBox("Recent Redemptions", mint_ops);
  auto* redemption_layout = new QVBoxLayout(redemption_box);
  auto* redemption_actions = new QHBoxLayout();
  mint_detail_button_ = new QPushButton("Selected Mint Details", redemption_box);
  redemption_actions->addStretch(1);
  redemption_actions->addWidget(mint_detail_button_);
  redemption_layout->addLayout(redemption_actions);
  mint_redemptions_view_ = new QListWidget(redemption_box);
  redemption_layout->addWidget(mint_redemptions_view_);
  mint_right->addWidget(redemption_box);

  mint_ops_layout->addLayout(mint_left, 3);
  mint_ops_layout->addLayout(mint_right, 4);
  mint_layout->addWidget(mint_ops);
  mint_layout->addStretch(1);
  tabs_->addTab(mint, "Mint");

  auto* settings = new QWidget(this);
  auto* settings_layout = new QVBoxLayout(settings);
  auto* settings_box = new QGroupBox("Connections", settings);
  auto* settings_form = new QFormLayout(settings_box);
  lightserver_url_edit_ = new QLineEdit(settings_box);
  mint_url_edit_ = new QLineEdit(settings_box);
  mint_id_edit_ = new QLineEdit(settings_box);
  settings_form->addRow("Lightserver URL", lightserver_url_edit_);
  settings_form->addRow("Mint URL", mint_url_edit_);
  settings_form->addRow("Mint ID (hex32)", mint_id_edit_);
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
  connect(history_detail_button_, &QPushButton::clicked, this, [this]() { show_selected_chain_detail(); });
  connect(mint_deposit_button, &QPushButton::clicked, this, [this]() { submit_mint_deposit(); });
  connect(mint_issue_button, &QPushButton::clicked, this, [this]() { issue_mint_note(); });
  connect(mint_redeem_button, &QPushButton::clicked, this, [this]() { submit_mint_redemption(); });
  connect(mint_redeem_status_button, &QPushButton::clicked, this, [this]() { refresh_mint_redemption_status(); });
  connect(mint_detail_button_, &QPushButton::clicked, this, [this]() { show_selected_mint_detail(); });
  connect(save_settings_button, &QPushButton::clicked, this, [this]() { save_connection_settings(); });
  connect(history_view_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem*) { show_selected_chain_detail(); });
  connect(mint_deposits_view_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem*) { show_selected_mint_detail(); });
  connect(mint_notes_view_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem*) { show_selected_mint_detail(); });
  connect(mint_redemptions_view_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem*) { show_selected_mint_detail(); });

  const QString mono = mono_font_family();
  history_view_->setFont(QFont(mono));
  mint_deposits_view_->setFont(QFont(mono));
  mint_notes_view_->setFont(QFont(mono));
  mint_redemptions_view_->setFont(QFont(mono));
}

void WalletWindow::load_settings() {
  QSettings settings(kSettingsOrg, kSettingsApp);
  lightserver_url_edit_->setText(settings.value("lightserver_url", "http://127.0.0.1:8080").toString());
  mint_url_edit_->setText(settings.value("mint_url", "http://127.0.0.1:8090").toString());
  mint_id_edit_->setText(settings.value("mint_id", "").toString());
}

void WalletWindow::save_settings() const {
  QSettings settings(kSettingsOrg, kSettingsApp);
  settings.setValue("lightserver_url", lightserver_url_edit_->text().trimmed());
  settings.setValue("mint_url", mint_url_edit_->text().trimmed());
  settings.setValue("mint_id", mint_id_edit_->text().trimmed());
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
  render_mint_state();
}

void WalletWindow::render_history_view() {
  history_view_->clear();
  if (chain_records_.empty() && local_history_lines_.empty()) {
    auto* item = new QListWidgetItem("No wallet history yet.", history_view_);
    item->setData(Qt::UserRole, -1);
    history_detail_button_->setEnabled(false);
    return;
  }
  for (std::size_t i = 0; i < chain_history_lines_.size(); ++i) {
    auto* item = new QListWidgetItem(chain_history_lines_[static_cast<int>(i)], history_view_);
    item->setData(Qt::UserRole, static_cast<int>(i));
  }
  if (!local_history_lines_.empty()) {
    auto* sep = new QListWidgetItem("---- Local Wallet Events ----", history_view_);
    sep->setFlags(Qt::NoItemFlags);
    for (const auto& line : local_history_lines_) {
      auto* item = new QListWidgetItem(line, history_view_);
      item->setData(Qt::UserRole, -1);
    }
  }
  history_detail_button_->setEnabled(!chain_records_.empty());
}

void WalletWindow::render_mint_state() {
  mint_deposit_ref_label_->setText(mint_deposit_ref_.isEmpty() ? "-" : mint_deposit_ref_);
  mint_redemption_label_->setText(mint_last_redemption_batch_id_.isEmpty() ? "-" : mint_last_redemption_batch_id_);
  std::uint64_t private_total = 0;
  std::map<std::uint64_t, std::size_t, std::greater<std::uint64_t>> by_amount;
  for (const auto& note : mint_notes_) {
    private_total += note.amount;
    by_amount[note.amount] += 1;
  }
  mint_records_.clear();
  mint_deposits_view_->clear();
  mint_notes_view_->clear();
  mint_redemptions_view_->clear();
  mint_private_balance_label_->setText(format_coin_amount(private_total));
  mint_note_count_label_->setText(QString::number(mint_notes_.size()));
  if (mint_notes_.empty()) {
    mint_notes_label_->setText("-");
    auto* item = new QListWidgetItem("No active private notes.", mint_notes_view_);
    item->setData(Qt::UserRole, -1);
  } else {
    QStringList summary_lines;
    mint_notes_view_->clear();
    for (const auto& [amount, count] : by_amount) {
      summary_lines.push_back(QString("%1 x %2").arg(QString::number(count), format_coin_amount(amount)));
    }
    for (const auto& note : mint_notes_) {
      const QString details = QString("%1  %2").arg(format_coin_amount(note.amount), elide_middle(note.note_ref, 10));
      auto* item = new QListWidgetItem(details, mint_notes_view_);
      mint_records_.push_back(MintRecord{"FINALIZED", "note", note.note_ref, format_coin_amount(note.amount), details});
      item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
    }
    mint_notes_label_->setText(summary_lines.join("\n"));
  }

  for (int i = local_history_lines_.size() - 1; i >= 0; --i) {
    const QString line = local_history_lines_[i];
    if (line.startsWith("[mint-deposit]")) {
      const QString details = trim_after_token(line, "[mint-deposit]");
      mint_records_.push_back(MintRecord{"PENDING", "deposit", mint_deposit_ref_, {}, details});
      auto* item = new QListWidgetItem(QString("%1 %2").arg(badge_text("PENDING"), details), mint_deposits_view_);
      item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
    } else if (line.startsWith("[mint-redeem]")) {
      const QString batch = extract_field_value(line, "batch");
      const QString amount = extract_field_value(line, "amount");
      const QString notes = extract_field_value(line, "notes");
      const QString details = QString("batch=%1  amount=%2  notes=%3").arg(batch, amount, notes);
      mint_records_.push_back(MintRecord{"PENDING", "redemption", batch, amount, details});
      auto* item = new QListWidgetItem(QString("%1 %2").arg(badge_text("PENDING"), details), mint_redemptions_view_);
      item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
    } else if (line.startsWith("[mint-status]")) {
      const QString batch = extract_field_value(line, "batch");
      const QString state = extract_field_value(line, "state");
      const QString txid = extract_field_value(line, "l1_txid");
      const QString details = QString("batch=%1  state=%2  tx=%3")
                                  .arg(batch, state, txid.isEmpty() ? "-" : elide_middle(txid, 8));
      mint_records_.push_back(MintRecord{mint_state_badge(state), "status", batch, {}, details});
      auto* item =
          new QListWidgetItem(QString("%1 %2").arg(badge_text(mint_state_badge(state)), details), mint_redemptions_view_);
      item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
    } else if (line.startsWith("[mint-issue]")) {
      const QString issuance = extract_field_value(line, "issuance");
      const QString amount = extract_field_value(line, "amount");
      const QString notes = extract_field_value(line, "notes");
      const QString details = QString("issuance=%1  amount=%2  notes=%3").arg(issuance, amount, notes);
      mint_records_.push_back(MintRecord{"FINALIZED", "issue", issuance, amount, details});
      auto* item = new QListWidgetItem(QString("%1 %2").arg(badge_text("FINALIZED"), details), mint_redemptions_view_);
      item->setData(Qt::UserRole, static_cast<int>(mint_records_.size() - 1));
    }
    if (mint_deposits_view_->count() >= 10 && mint_redemptions_view_->count() >= 12) break;
  }
  if (mint_deposits_view_->count() == 0) {
    auto* item = new QListWidgetItem("No mint deposits recorded yet.", mint_deposits_view_);
    item->setData(Qt::UserRole, -1);
  }
  if (mint_redemptions_view_->count() == 0) {
    auto* item = new QListWidgetItem("No redemptions recorded yet.", mint_redemptions_view_);
    item->setData(Qt::UserRole, -1);
  }
  mint_detail_button_->setEnabled(!mint_records_.empty());
}

void WalletWindow::save_wallet_local_state() {
  if (!wallet_) return;
  (void)store_.set_mint_deposit_ref(mint_deposit_ref_.toStdString());
  (void)store_.set_mint_last_deposit_txid(mint_last_deposit_txid_.toStdString());
  (void)store_.set_mint_last_deposit_vout(mint_last_deposit_vout_);
  (void)store_.set_mint_last_redemption_batch_id(mint_last_redemption_batch_id_.toStdString());
  for (const auto& note : mint_notes_) {
    (void)store_.upsert_mint_note(note.note_ref.toStdString(), note.amount, true);
  }
}

void WalletWindow::load_wallet_local_state() {
  local_sent_txids_.clear();
  local_history_lines_.clear();
  mint_notes_.clear();
  if (!wallet_ || !open_wallet_store()) return;
  WalletStore::State state;
  if (!store_.load(&state)) return;
  local_sent_txids_ = state.sent_txids;
  for (const auto& line : state.local_events) local_history_lines_.push_back(QString::fromStdString(line));
  mint_deposit_ref_ = QString::fromStdString(state.mint_deposit_ref);
  mint_last_deposit_txid_ = QString::fromStdString(state.mint_last_deposit_txid);
  mint_last_deposit_vout_ = state.mint_last_deposit_vout;
  mint_last_redemption_batch_id_ = QString::fromStdString(state.mint_last_redemption_batch_id);
  for (const auto& note : state.mint_notes) {
    if (note.active) mint_notes_.push_back(MintNote{QString::fromStdString(note.note_ref), note.amount});
  }
  render_mint_state();
}

bool WalletWindow::open_wallet_store() {
  if (!wallet_) return false;
  return store_.open(wallet_->file_path);
}

void WalletWindow::append_local_event(const QString& line) {
  local_history_lines_.push_back(line);
  if (wallet_) (void)store_.append_local_event(line.toStdString());
  render_history_view();
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
  chain_history_lines_.clear();
  chain_records_.clear();
  const auto own_decoded = selfcoin::address::decode(wallet_->address);
  const Bytes own_spk = own_decoded ? selfcoin::address::p2pkh_script_pubkey(own_decoded->pubkey_hash) : Bytes{};
  std::reverse(history->begin(), history->end());
  std::set<std::string> finalized_seen;
  for (const auto& entry : *history) {
    const std::string txid_hex = hex_encode32(entry.txid);
    finalized_seen.insert(txid_hex);
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
    const QString txid_q = QString::fromStdString(txid_hex);
    const QString line = QString("%1 %2  %3  height=%4  tx=%5")
                             .arg(badge_text("FINALIZED"))
                             .arg(kind.toUpper())
                             .arg(detail)
                             .arg(entry.height)
                             .arg(elide_middle(txid_q, 12));
    chain_history_lines_.push_back(line);
    chain_records_.push_back(ChainRecord{"FINALIZED", kind.toUpper(), detail, txid_q,
                                         QString("Height: %1\nTransaction: %2\nAmount/Detail: %3")
                                             .arg(entry.height)
                                             .arg(txid_q)
                                             .arg(detail)});
  }
  for (const auto& txid_hex : local_sent_txids_) {
    if (finalized_seen.count(txid_hex)) continue;
    const QString txid_q = QString::fromStdString(txid_hex);
    const QString line = QString("%1 SENT  awaiting finalization  tx=%2")
                             .arg(badge_text("PENDING"))
                             .arg(elide_middle(txid_q, 12));
    chain_history_lines_.push_back(line);
    chain_records_.push_back(ChainRecord{"PENDING", "SENT", "awaiting finalization", txid_q,
                                         QString("Transaction: %1\nState: pending broadcast/finality observation").arg(txid_q)});
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
  (void)open_wallet_store();
  load_wallet_local_state();
  update_wallet_views();
  append_local_event("Created wallet at " + path);
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
  (void)open_wallet_store();
  load_wallet_local_state();
  update_wallet_views();
  append_local_event("Opened wallet " + path);
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
  (void)open_wallet_store();
  load_wallet_local_state();
  update_wallet_views();
  append_local_event("Imported wallet into " + path);
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
  append_local_event("Exported backup material for " + QString::fromStdString(wallet_->file_path));
}

void WalletWindow::save_connection_settings() {
  save_settings();
  update_connection_views();
  append_local_event("Saved local connection settings.");
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
  (void)store_.add_sent_txid(result->txid_hex);
  save_wallet_local_state();
  append_local_event(QString("[pending] sent %1 -> %2 (%3)")
                         .arg(format_coin_amount(*amount_units))
                         .arg(elide_middle(destination))
                         .arg(elide_middle(QString::fromStdString(result->txid_hex), 12)));
  refresh_chain_state(false);
  statusBar()->showMessage("Transaction broadcasted.", 3000);
}

void WalletWindow::show_selected_chain_detail() {
  auto* item = history_view_->currentItem();
  if (!item) {
    QMessageBox::information(this, "Transaction Details", "Select a transaction row first.");
    return;
  }
  const int index = item->data(Qt::UserRole).toInt();
  if (index < 0 || static_cast<std::size_t>(index) >= chain_records_.size()) {
    QMessageBox::information(this, "Transaction Details", "The selected row does not have transaction details.");
    return;
  }
  const auto& rec = chain_records_[static_cast<std::size_t>(index)];
  QMessageBox::information(
      this, "Transaction Details",
      QString("Status: %1\nType: %2\nAmount/Detail: %3\nTXID: %4\n\n%5")
          .arg(rec.status, rec.kind, rec.amount, rec.txid, rec.details));
}

void WalletWindow::show_selected_mint_detail() {
  QListWidgetItem* item = nullptr;
  if (mint_deposits_view_->hasFocus()) item = mint_deposits_view_->currentItem();
  if (!item && mint_notes_view_->hasFocus()) item = mint_notes_view_->currentItem();
  if (!item && mint_redemptions_view_->hasFocus()) item = mint_redemptions_view_->currentItem();
  if (!item) item = mint_redemptions_view_->currentItem();
  if (!item) item = mint_deposits_view_->currentItem();
  if (!item) item = mint_notes_view_->currentItem();
  if (!item) {
    QMessageBox::information(this, "Mint Details", "Select a mint row first.");
    return;
  }
  const int index = item->data(Qt::UserRole).toInt();
  if (index < 0 || static_cast<std::size_t>(index) >= mint_records_.size()) {
    QMessageBox::information(this, "Mint Details", "The selected row does not have mint details.");
    return;
  }
  const auto& rec = mint_records_[static_cast<std::size_t>(index)];
  QMessageBox::information(
      this, "Mint Details",
      QString("Status: %1\nKind: %2\nReference: %3\nAmount: %4\n\n%5")
          .arg(rec.status,
               rec.kind,
               rec.reference.isEmpty() ? "-" : rec.reference,
               rec.amount.isEmpty() ? "-" : rec.amount,
               rec.details));
}

void WalletWindow::submit_mint_deposit() {
  if (!ensure_wallet_loaded("Mint Deposit")) return;
  const QString rpc_url = lightserver_url_edit_->text().trimmed();
  const QString mint_url = mint_url_edit_->text().trimmed();
  const QString mint_id_hex = mint_id_edit_->text().trimmed();
  if (rpc_url.isEmpty() || mint_url.isEmpty() || mint_id_hex.isEmpty()) {
    QMessageBox::warning(this, "Mint Deposit", "Configure lightserver URL, mint URL, and mint ID first.");
    return;
  }
  auto mint_id = decode_hex32_string(mint_id_hex.toStdString());
  if (!mint_id) {
    QMessageBox::warning(this, "Mint Deposit", "Mint ID must be 32-byte hex.");
    return;
  }
  auto amount_units = parse_coin_amount(mint_deposit_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    QMessageBox::warning(this, "Mint Deposit", "Enter a valid deposit amount.");
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
    if (selected >= *amount_units) break;
  }
  if (selected < *amount_units) {
    QMessageBox::warning(this, "Mint Deposit", "Insufficient confirmed UTXOs.");
    return;
  }

  std::string err;
  auto key = load_wallet_key(&err);
  if (!key) {
    QMessageBox::warning(this, "Mint Deposit", QString::fromStdString(err));
    return;
  }
  auto own_decoded = selfcoin::address::decode(wallet_->address);
  if (!own_decoded) {
    QMessageBox::warning(this, "Mint Deposit", "Wallet address is invalid.");
    return;
  }
  std::vector<TxOut> outputs;
  outputs.push_back(TxOut{
      *amount_units, selfcoin::privacy::mint_deposit_script_pubkey(*mint_id, own_decoded->pubkey_hash)});
  const std::uint64_t change = selected - *amount_units;
  if (change > 0) outputs.push_back(TxOut{change, selfcoin::address::p2pkh_script_pubkey(own_decoded->pubkey_hash)});

  auto tx = selfcoin::build_signed_p2pkh_tx_multi_input(
      prevs, selfcoin::Bytes(key->privkey.begin(), key->privkey.end()), outputs, &err);
  if (!tx) {
    QMessageBox::warning(this, "Mint Deposit", QString::fromStdString(err));
    return;
  }
  auto broadcast = lightserver::rpc_broadcast_tx(rpc_url.toStdString(), tx->serialize(), &err);
  if (!broadcast || !broadcast->accepted) {
    const QString reason = broadcast ? QString::fromStdString(broadcast->error) : QString::fromStdString(err);
    QMessageBox::warning(this, "Mint Deposit", "Broadcast failed: " + reason);
    return;
  }

  selfcoin::privacy::MintDepositRegistrationRequest req;
  req.chain = "mainnet";
  req.deposit_txid = tx->txid();
  req.deposit_vout = 0;
  req.mint_id = *mint_id;
  req.recipient_pubkey_hash = own_decoded->pubkey_hash;
  req.amount = *amount_units;
  auto reg_body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/deposits/register").toStdString(),
                                                  selfcoin::privacy::to_json(req), &err);
  if (!reg_body) {
    QMessageBox::warning(this, "Mint Deposit", "Mint registration failed: " + QString::fromStdString(err));
    return;
  }
  auto reg = selfcoin::privacy::parse_mint_deposit_registration_response(*reg_body);
  if (!reg || !reg->accepted) {
    QMessageBox::warning(this, "Mint Deposit", "Mint registration was rejected.");
    return;
  }

  mint_deposit_ref_ = QString::fromStdString(reg->mint_deposit_ref);
  mint_last_deposit_txid_ = QString::fromStdString(hex_encode32(tx->txid()));
  mint_last_deposit_vout_ = 0;
  save_wallet_local_state();
  render_mint_state();
  append_local_event(QString("[mint-deposit] %1 %2 ref=%3")
                         .arg(format_coin_amount(*amount_units))
                         .arg(elide_middle(mint_last_deposit_txid_, 12))
                         .arg(mint_deposit_ref_));
  refresh_chain_state(false);
  statusBar()->showMessage("Mint deposit broadcasted and registered.", 3000);
}

void WalletWindow::issue_mint_note() {
  if (!ensure_wallet_loaded("Issue Note")) return;
  const QString mint_url = mint_url_edit_->text().trimmed();
  if (mint_url.isEmpty() || mint_deposit_ref_.isEmpty()) {
    QMessageBox::warning(this, "Issue Note", "Create and register a mint deposit first.");
    return;
  }
  auto amount_units = parse_coin_amount(mint_issue_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    QMessageBox::warning(this, "Issue Note", "Enter a valid issue amount.");
    return;
  }
  const auto denominations = split_into_denominations(*amount_units);
  if (denominations.empty()) {
    QMessageBox::warning(this, "Issue Note", "Failed to derive note denominations.");
    return;
  }

  selfcoin::privacy::MintBlindIssueRequest req;
  req.mint_deposit_ref = mint_deposit_ref_.toStdString();
  for (const auto denom : denominations) {
    req.blinded_messages.push_back(random_hex_string(64).toStdString());
    req.note_amounts.push_back(denom);
  }

  std::string err;
  auto body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/issuance/blind").toStdString(),
                                              selfcoin::privacy::to_json(req), &err);
  if (!body) {
    QMessageBox::warning(this, "Issue Note", "Mint issuance failed: " + QString::fromStdString(err));
    return;
  }
  auto resp = selfcoin::privacy::parse_mint_blind_issue_response(*body);
  if (!resp || resp->note_refs.empty()) {
    QMessageBox::warning(this, "Issue Note", "Mint issuance response was invalid.");
    return;
  }

  for (std::size_t i = 0; i < resp->note_refs.size(); ++i) {
    const std::uint64_t amount = i < resp->note_amounts.size() ? resp->note_amounts[i] : *amount_units;
    mint_notes_.push_back(MintNote{QString::fromStdString(resp->note_refs[i]), amount});
    (void)store_.upsert_mint_note(resp->note_refs[i], amount, true);
  }
  save_wallet_local_state();
  render_mint_state();
  append_local_event(QString("[mint-issue] issuance=%1 amount=%2 notes=%3")
                         .arg(QString::fromStdString(resp->issuance_id))
                         .arg(format_coin_amount(*amount_units))
                         .arg(resp->note_refs.size()));
  statusBar()->showMessage("Mint note issued.", 3000);
}

void WalletWindow::submit_mint_redemption() {
  if (!ensure_wallet_loaded("Redeem")) return;
  const QString mint_url = mint_url_edit_->text().trimmed();
  if (mint_url.isEmpty()) {
    QMessageBox::warning(this, "Redeem", "Configure a mint URL first.");
    return;
  }
  const QString redeem_address = mint_redeem_address_edit_->text().trimmed();
  if (!selfcoin::address::decode(redeem_address.toStdString()).has_value()) {
    QMessageBox::warning(this, "Redeem", "Destination address is invalid.");
    return;
  }
  auto amount_units = parse_coin_amount(mint_redeem_amount_edit_->text());
  if (!amount_units || *amount_units == 0) {
    QMessageBox::warning(this, "Redeem", "Enter a valid redemption amount.");
    return;
  }

  auto selected_indexes = choose_note_subset_exact(mint_notes_, *amount_units);
  if (!selected_indexes) {
    QMessageBox::warning(this, "Redeem", "No exact note combination matches that redemption amount.");
    return;
  }
  std::vector<std::string> selected_notes;
  for (auto idx : *selected_indexes) selected_notes.push_back(mint_notes_[idx].note_ref.toStdString());

  selfcoin::privacy::MintRedemptionRequest req;
  req.notes = selected_notes;
  req.redeem_address = redeem_address.toStdString();
  req.amount = *amount_units;
  std::string err;
  auto body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/redemptions/create").toStdString(),
                                              selfcoin::privacy::to_json(req), &err);
  if (!body) {
    QMessageBox::warning(this, "Redeem", "Mint redemption failed: " + QString::fromStdString(err));
    return;
  }
  auto resp = selfcoin::privacy::parse_mint_redemption_response(*body);
  if (!resp || !resp->accepted) {
    QMessageBox::warning(this, "Redeem", "Mint redemption was rejected.");
    return;
  }

  mint_last_redemption_batch_id_ = QString::fromStdString(resp->redemption_batch_id);
  for (const auto& note_ref : selected_notes) {
    auto it = std::find_if(mint_notes_.begin(), mint_notes_.end(),
                           [&](const MintNote& note) { return note.note_ref.toStdString() == note_ref; });
    if (it != mint_notes_.end()) (void)store_.upsert_mint_note(note_ref, it->amount, false);
    mint_notes_.erase(std::remove_if(mint_notes_.begin(), mint_notes_.end(),
                                     [&](const MintNote& note) { return note.note_ref.toStdString() == note_ref; }),
                      mint_notes_.end());
  }
  save_wallet_local_state();
  render_mint_state();
  append_local_event(QString("[mint-redeem] batch=%1 amount=%2 notes=%3")
                         .arg(mint_last_redemption_batch_id_)
                         .arg(format_coin_amount(*amount_units))
                         .arg(selected_notes.size()));
  statusBar()->showMessage("Mint redemption created.", 3000);
}

void WalletWindow::refresh_mint_redemption_status() {
  if (mint_last_redemption_batch_id_.isEmpty()) {
    QMessageBox::information(this, "Redemption Status", "No redemption batch has been created yet.");
    return;
  }
  const QString mint_url = mint_url_edit_->text().trimmed();
  if (mint_url.isEmpty()) {
    QMessageBox::warning(this, "Redemption Status", "Configure a mint URL first.");
    return;
  }
  std::ostringstream body_json;
  body_json << "{\"redemption_batch_id\":\"" << mint_last_redemption_batch_id_.toStdString() << "\"}";
  std::string err;
  auto body = lightserver::http_post_json_raw(mint_endpoint(mint_url, "/redemptions/status").toStdString(),
                                              body_json.str(), &err);
  if (!body) {
    QMessageBox::warning(this, "Redemption Status", "Status query failed: " + QString::fromStdString(err));
    return;
  }
  auto resp = selfcoin::privacy::parse_mint_redemption_status_response(*body);
  if (!resp) {
    QMessageBox::warning(this, "Redemption Status", "Status response was invalid.");
    return;
  }
  mint_status_label_->setText(QString("Redemption %1: state=%2 l1_txid=%3 amount=%4")
                                  .arg(mint_last_redemption_batch_id_)
                                  .arg(QString::fromStdString(resp->state))
                                  .arg(QString::fromStdString(resp->l1_txid))
                                  .arg(format_coin_amount(resp->amount)));
  append_local_event(QString("[mint-status] batch=%1 state=%2 l1_txid=%3")
                         .arg(mint_last_redemption_batch_id_)
                         .arg(QString::fromStdString(resp->state))
                         .arg(elide_middle(QString::fromStdString(resp->l1_txid), 12)));
}

}  // namespace selfcoin::wallet
