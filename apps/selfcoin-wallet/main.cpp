#include <QApplication>

#include "wallet_window.hpp"

int main(int argc, char* argv[]) {
  QApplication app(argc, argv);
  QApplication::setOrganizationName("selfcoin");
  QApplication::setApplicationName("reference-wallet");

  selfcoin::wallet::WalletWindow window;
  window.show();
  return app.exec();
}
