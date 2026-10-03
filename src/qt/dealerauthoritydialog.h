// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_DEALERAUTHORITYDIALOG_H
#define BITCOIN_QT_DEALERAUTHORITYDIALOG_H

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <univalue.h>

#include <QDialog>
#include <QPointer>

#include <functional>
#include <string>

class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class WalletModel;
namespace interfaces { class Node; }

/** Offline quorum coordination. Authority private keys never enter the GUI. */
class DealerAuthorityDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DealerAuthorityDialog(interfaces::Node& node, QWidget* parent = nullptr);
#ifdef ENABLE_WALLET
    void setWalletModel(WalletModel* wallet);
#endif

private:
    void guarded(const std::function<void()>& action);
    void invalidate();
    void refresh();
    void prepare();
    void verify();
    void exportProposal();
#ifdef ENABLE_WALLET
    void submit();
    QPointer<WalletModel> m_wallet;
#endif
    UniValue call(const char* method, UniValue parameters = UniValue{UniValue::VARR}, const std::string& uri = {});
    UniValue build(const UniValue& parameters);
    std::string operation() const;

    interfaces::Node& m_node;
    UniValue m_info;
    UniValue m_parameters;
    UniValue m_proposal;
    QPlainTextEdit* m_status;
    QComboBox* m_operation;
    QLineEdit* m_dealer;
    QLineEdit* m_control;
    QLineEdit* m_payout;
    QSpinBox* m_licenses;
    QPlainTextEdit* m_next_keys;
    QPlainTextEdit* m_signatures;
    QPlainTextEdit* m_next_signatures;
    QPlainTextEdit* m_details;
    QPushButton* m_prepare;
    QPushButton* m_verify;
    QPushButton* m_export;
    QPushButton* m_submit;
};

#endif // BITCOIN_QT_DEALERAUTHORITYDIALOG_H
