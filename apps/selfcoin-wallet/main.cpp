#include <QApplication>
#include <QPalette>
#include <QStyleFactory>

#include "wallet_window.hpp"

int main(int argc, char* argv[]) {
  QApplication app(argc, argv);
  QApplication::setOrganizationName("selfcoin");
  QApplication::setApplicationName("reference-wallet");
  if (auto* style = QStyleFactory::create("Fusion")) app.setStyle(style);
  QPalette palette;
  palette.setColor(QPalette::Window, QColor(236, 236, 236));
  palette.setColor(QPalette::WindowText, Qt::black);
  palette.setColor(QPalette::Base, Qt::white);
  palette.setColor(QPalette::AlternateBase, QColor(244, 244, 244));
  palette.setColor(QPalette::ToolTipBase, Qt::white);
  palette.setColor(QPalette::ToolTipText, Qt::black);
  palette.setColor(QPalette::Text, Qt::black);
  palette.setColor(QPalette::Button, QColor(230, 230, 230));
  palette.setColor(QPalette::ButtonText, Qt::black);
  palette.setColor(QPalette::Highlight, QColor(10, 88, 170));
  palette.setColor(QPalette::HighlightedText, Qt::white);
  app.setPalette(palette);

  selfcoin::wallet::WalletWindow window;
  window.show();
  return app.exec();
}
