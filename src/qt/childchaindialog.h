// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CHILDCHAINDIALOG_H
#define BITCOIN_QT_CHILDCHAINDIALOG_H

#include <QDialog>

class QLabel;
class QPushButton;
class QTableWidget;

namespace interfaces {
class Node;
}

/** Catalog and local runtime controls for registered child chains. */
class ChildChainDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ChildChainDialog(interfaces::Node& node, QWidget* parent = nullptr);

private Q_SLOTS:
    void refresh();
    void updateSelection();
    void loadSelected();
    void unloadSelected();
    void forgetSelected();
    void addManifest();

private:
    enum Column {
        STATUS,
        CHAIN_ID,
        CHILD_HEIGHT,
        MAIN_HEIGHT,
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
    };

    QString selectedChainId() const;
    bool runLifecycleCommand(const char* command, const QString& chain_id);
    void showRpcError(const QString& operation, const QString& message);

    interfaces::Node& m_node;
    QLabel* m_registry_summary{nullptr};
    QLabel* m_selection_summary{nullptr};
    QTableWidget* m_table{nullptr};
    QPushButton* m_refresh_button{nullptr};
    QPushButton* m_add_button{nullptr};
    QPushButton* m_load_button{nullptr};
    QPushButton* m_unload_button{nullptr};
    QPushButton* m_forget_button{nullptr};
};

#endif // BITCOIN_QT_CHILDCHAINDIALOG_H
