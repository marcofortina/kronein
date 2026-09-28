// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CHILDCHAINDIALOG_H
#define BITCOIN_QT_CHILDCHAINDIALOG_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <QDialog>
#ifdef ENABLE_WALLET
#include <QPointer>
#endif

#include <string>

class QLabel;
class QPushButton;
class QTableWidget;
class UniValue;
#ifdef ENABLE_WALLET
class WalletModel;
#endif

namespace interfaces {
class Node;
}

/** Catalog and local runtime controls for registered child chains. */
class ChildChainDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ChildChainDialog(interfaces::Node& node, QWidget* parent = nullptr);
#ifdef ENABLE_WALLET
    void setWalletModel(WalletModel* wallet_model);
#endif

private Q_SLOTS:
    void refresh();
    void updateSelection();
    void loadSelected();
    void unloadSelected();
    void forgetSelected();
    void addManifest();
    void addPeer();
    void removePeer();
    void configureBinds();
    void configureDiscovery();
    void toggleNetwork();
    void manageBmm();
#ifdef ENABLE_WALLET
    void registerChildChain();
    void showBalance();
    void receiveSelected();
    void sendSelected();
    void showActivity();
    void showDeposits();
    void migrateSelected();
    void updateSelected();
    void retireSelected();
#endif

private:
    enum Column {
        STATUS,
        CHAIN_ID,
        CHILD_HEIGHT,
        MAIN_HEIGHT,
        NETWORK,
        FORK_DAG,
        TEMPLATE,
        SAFETY,
        COLUMN_COUNT,
    };

    enum DataRole {
        CHAIN_ID_ROLE = Qt::UserRole,
        CONFIGURED_ROLE,
        LOADED_ROLE,
        REGISTRY_FOUND_ROLE,
        STATE_ROLE,
        NETWORK_RUNNING_ROLE,
        NETWORK_ACTIVE_ROLE,
        ADDED_NODES_ROLE,
        BINDS_ROLE,
        DISCOVERY_ROLE,
        BOOTSTRAP_NODES_ROLE,
        KNOWN_ADDRESSES_ROLE,
        RATE_LIMITED_REQUESTS_ROLE,
        SUPPORTED_ROLE,
        METADATA_HASH_ROLE,
    };

    QString selectedChainId() const;
    bool runCommand(const char* command, UniValue params);
    bool runLifecycleCommand(const char* command, const QString& chain_id);
    void showRpcError(const QString& operation, const QString& message);
    void showBmmStatus(const QString& chain_id);
    void activateBmmProposal(const QString& chain_id);
#ifdef ENABLE_WALLET
    std::string walletUri() const;
    void createBmmProposal(const QString& chain_id);
    void submitRegistryOperation(const char* operation,
                                 const QString& chain_id,
                                 UniValue parameters,
                                 const QString& result_details = {});
#endif

    interfaces::Node& m_node;
    QLabel* m_registry_summary{nullptr};
    QLabel* m_selection_summary{nullptr};
    QTableWidget* m_table{nullptr};
    QPushButton* m_refresh_button{nullptr};
    QPushButton* m_add_button{nullptr};
    QPushButton* m_load_button{nullptr};
    QPushButton* m_unload_button{nullptr};
    QPushButton* m_forget_button{nullptr};
    QPushButton* m_add_peer_button{nullptr};
    QPushButton* m_remove_peer_button{nullptr};
    QPushButton* m_binds_button{nullptr};
    QPushButton* m_discovery_button{nullptr};
    QPushButton* m_network_button{nullptr};
    QPushButton* m_bmm_button{nullptr};
#ifdef ENABLE_WALLET
    QPointer<WalletModel> m_wallet_model;
    QPushButton* m_register_button{nullptr};
    QPushButton* m_balance_button{nullptr};
    QPushButton* m_receive_button{nullptr};
    QPushButton* m_send_button{nullptr};
    QPushButton* m_activity_button{nullptr};
    QPushButton* m_deposits_button{nullptr};
    QPushButton* m_migrate_button{nullptr};
    QPushButton* m_update_button{nullptr};
    QPushButton* m_retire_button{nullptr};
#endif
};

#endif // BITCOIN_QT_CHILDCHAINDIALOG_H
