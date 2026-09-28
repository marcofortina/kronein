// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/childchaindialog.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QAbstractItemView>
#include <QApplication>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QVariant>

#include <exception>
#include <stdexcept>
#include <utility>

namespace {

QString StringField(const UniValue& object, const char* name)
{
    const UniValue& value{object.find_value(name)};
    return value.isStr() ? QString::fromStdString(value.get_str()) : QString{};
}

QString NumberField(const UniValue& object, const char* name)
{
    const UniValue& value{object.find_value(name)};
    return value.isNum() ? QString::fromStdString(value.getValStr()) : QStringLiteral("—");
}

bool BoolField(const UniValue& object, const char* name)
{
    const UniValue& value{object.find_value(name)};
    return value.isBool() && value.get_bool();
}

QStringList StringArrayField(const UniValue& object, const char* name)
{
    QStringList result;
    const UniValue& values{object.find_value(name)};
    if (!values.isArray()) return result;
    for (const UniValue& value : values.getValues()) {
        if (value.isStr()) result.push_back(QString::fromStdString(value.get_str()));
    }
    return result;
}

QString RpcErrorMessage(const UniValue& error)
{
    const UniValue& message{error.find_value("message")};
    return message.isStr() ? QString::fromStdString(message.get_str())
                           : QString::fromStdString(error.write());
}

QString StateLabel(const QString& state)
{
    if (state == QStringLiteral("available")) return ChildChainDialog::tr("Available");
    if (state == QStringLiteral("configured")) return ChildChainDialog::tr("Configured");
    if (state == QStringLiteral("loaded")) return ChildChainDialog::tr("Loaded");
    if (state == QStringLiteral("retired")) return ChildChainDialog::tr("Retired");
    if (state == QStringLiteral("unsupported-template")) return ChildChainDialog::tr("Unsupported template");
    if (state == QStringLiteral("manifest-mismatch")) return ChildChainDialog::tr("Manifest mismatch");
    if (state == QStringLiteral("orphaned")) return ChildChainDialog::tr("Not in registry");
    return state;
}

} // namespace

ChildChainDialog::ChildChainDialog(interfaces::Node& node, QWidget* parent)
    : QDialog{parent}, m_node{node}
{
    setWindowTitle(tr("Child Chains"));
    setMinimumSize(1250, 520);

    m_registry_summary = new QLabel{this};
    m_registry_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_registry_summary->setWordWrap(true);

    m_table = new QTableWidget{this};
    m_table->setObjectName(QStringLiteral("childChainTable"));
    m_table->setColumnCount(COLUMN_COUNT);
    m_table->setHorizontalHeaderLabels({
        tr("Status"),
        tr("Chain ID"),
        tr("Child height"),
        tr("Main height"),
        tr("Network"),
        tr("Fork DAG"),
        tr("Template"),
        tr("Safety"),
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(STATUS, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(CHAIN_ID, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(CHILD_HEIGHT, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(MAIN_HEIGHT, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(NETWORK, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(FORK_DAG, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(TEMPLATE, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(SAFETY, QHeaderView::ResizeToContents);

    m_selection_summary = new QLabel{tr("Select a child chain to manage its local runtime."), this};
    m_selection_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_selection_summary->setWordWrap(true);

    auto* actions = new QDialogButtonBox{this};
    m_refresh_button = actions->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    m_add_button = actions->addButton(tr("Add Manifest…"), QDialogButtonBox::ActionRole);
    m_load_button = actions->addButton(tr("Load"), QDialogButtonBox::ActionRole);
    m_unload_button = actions->addButton(tr("Unload"), QDialogButtonBox::ActionRole);
    m_add_peer_button = actions->addButton(tr("Add Peer…"), QDialogButtonBox::ActionRole);
    m_remove_peer_button = actions->addButton(tr("Remove Peer…"), QDialogButtonBox::ActionRole);
    m_binds_button = actions->addButton(tr("Listening…"), QDialogButtonBox::ActionRole);
    m_network_button = actions->addButton(tr("Pause Network"), QDialogButtonBox::ActionRole);
    m_add_peer_button->setObjectName(QStringLiteral("childChainAddPeerButton"));
    m_remove_peer_button->setObjectName(QStringLiteral("childChainRemovePeerButton"));
    m_binds_button->setObjectName(QStringLiteral("childChainBindsButton"));
    m_network_button->setObjectName(QStringLiteral("childChainNetworkButton"));
    m_forget_button = actions->addButton(tr("Forget…"), QDialogButtonBox::DestructiveRole);
    actions->addButton(QDialogButtonBox::Close);

    auto* layout = new QVBoxLayout{this};
    layout->addWidget(m_registry_summary);
    layout->addWidget(m_table, 1);
    layout->addWidget(m_selection_summary);
    layout->addWidget(actions);

    connect(m_table, &QTableWidget::itemSelectionChanged, this, &ChildChainDialog::updateSelection);
    connect(m_refresh_button, &QPushButton::clicked, this, &ChildChainDialog::refresh);
    connect(m_add_button, &QPushButton::clicked, this, &ChildChainDialog::addManifest);
    connect(m_load_button, &QPushButton::clicked, this, &ChildChainDialog::loadSelected);
    connect(m_unload_button, &QPushButton::clicked, this, &ChildChainDialog::unloadSelected);
    connect(m_add_peer_button, &QPushButton::clicked, this, &ChildChainDialog::addPeer);
    connect(m_remove_peer_button, &QPushButton::clicked, this, &ChildChainDialog::removePeer);
    connect(m_binds_button, &QPushButton::clicked, this, &ChildChainDialog::configureBinds);
    connect(m_network_button, &QPushButton::clicked, this, &ChildChainDialog::toggleNetwork);
    connect(m_forget_button, &QPushButton::clicked, this, &ChildChainDialog::forgetSelected);
    connect(actions, &QDialogButtonBox::rejected, this, &QDialog::close);

    updateSelection();
    refresh();
}

void ChildChainDialog::refresh()
{
    m_refresh_button->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        const UniValue result{m_node.executeRpc("listchildchainruntimes", UniValue{UniValue::VARR}, "")};
        const UniValue& chains{result.find_value("chains")};
        if (!result.isObject() || !chains.isArray()) {
            throw std::runtime_error{"listchildchainruntimes returned an invalid result"};
        }

        const QString selected{selectedChainId()};
        m_table->setSortingEnabled(false);
        m_table->setRowCount(0);
        for (const UniValue& chain : chains.getValues()) {
            if (!chain.isObject()) continue;

            const QString chain_id{StringField(chain, "chain_id")};
            if (chain_id.isEmpty()) continue;
            const bool configured{BoolField(chain, "configured")};
            const bool loaded{BoolField(chain, "loaded")};
            const bool registry_found{BoolField(chain, "registry_found")};
            const bool failed{BoolField(chain, "failed")};
            const bool safe_halt{BoolField(chain, "safe_halt")};
            const bool network_running{BoolField(chain, "network_running")};
            const bool network_active{BoolField(chain, "network_active")};
            const QString connections{NumberField(chain, "connections")};
            const QString handshaken{NumberField(chain, "handshaken_peers")};
            const QStringList added_nodes{StringArrayField(chain, "added_nodes")};
            const QStringList binds{StringArrayField(chain, "binds")};
            const QString state{StringField(chain, "state")};
            const QString template_name{QStringLiteral("%1/%2")
                .arg(NumberField(chain, "template_id"), NumberField(chain, "template_version"))};
            const QString safety{failed ? tr("Failed") : safe_halt ? tr("Safe halt") : tr("Normal")};
            const QString side_candidates{NumberField(chain, "side_candidate_count")};
            const QString side_candidate_limit{NumberField(chain, "side_candidate_limit")};
            const QString candidate_anchors{NumberField(chain, "candidate_bmm_anchor_count")};
            const QString candidate_anchor_limit{NumberField(chain, "candidate_bmm_anchor_limit")};
            const QString pending_blocks{NumberField(chain, "pending_child_block_count")};
            const QString dag_usage{loaded
                ? tr("%1 pending • %2/%3 candidates • %4/%5 anchors")
                      .arg(pending_blocks,
                           side_candidates,
                           side_candidate_limit,
                           candidate_anchors,
                           candidate_anchor_limit)
                : QStringLiteral("—")};
            const QString network_state{!network_running
                ? tr("Stopped")
                : !network_active
                    ? tr("Paused")
                    : tr("%1 connected • %2 authenticated")
                          .arg(connections, handshaken)};

            const int row{m_table->rowCount()};
            m_table->insertRow(row);
            auto* status_item = new QTableWidgetItem{StateLabel(state)};
            status_item->setData(CHAIN_ID_ROLE, chain_id);
            status_item->setData(CONFIGURED_ROLE, configured);
            status_item->setData(LOADED_ROLE, loaded);
            status_item->setData(REGISTRY_FOUND_ROLE, registry_found);
            status_item->setData(STATE_ROLE, state);
            status_item->setData(NETWORK_RUNNING_ROLE, network_running);
            status_item->setData(NETWORK_ACTIVE_ROLE, network_active);
            status_item->setData(ADDED_NODES_ROLE, added_nodes);
            status_item->setData(BINDS_ROLE, binds);
            m_table->setItem(row, STATUS, status_item);
            m_table->setItem(row, CHAIN_ID, new QTableWidgetItem{chain_id});
            m_table->setItem(row, CHILD_HEIGHT, new QTableWidgetItem{NumberField(chain, "child_height")});
            m_table->setItem(row, MAIN_HEIGHT, new QTableWidgetItem{NumberField(chain, "main_height")});
            auto* network_item = new QTableWidgetItem{network_state};
            const QString outbound_tooltip{added_nodes.isEmpty()
                ? tr("No explicit child peers configured")
                : tr("Explicit child peers:\n%1").arg(added_nodes.join(QLatin1Char('\n')))};
            const QString inbound_tooltip{binds.isEmpty()
                ? tr("Inbound child connections disabled")
                : tr("Child listen endpoints:\n%1").arg(binds.join(QLatin1Char('\n')))};
            network_item->setToolTip(
                outbound_tooltip + QStringLiteral("\n\n") + inbound_tooltip);
            m_table->setItem(row, NETWORK, network_item);
            auto* dag_item = new QTableWidgetItem{dag_usage};
            m_table->setItem(row, FORK_DAG, dag_item);
            m_table->setItem(row, TEMPLATE, new QTableWidgetItem{template_name});
            m_table->setItem(row, SAFETY, new QTableWidgetItem{safety});

            for (int column = 0; column < COLUMN_COUNT; ++column) {
                if (column == NETWORK) continue;
                m_table->item(row, column)->setToolTip(chain_id);
            }
            if (loaded) {
                const QString storage_tooltip{
                    tr("Side candidates: %1/%2 records, %3/%4 bytes\n"
                       "Candidate BMM anchors: %5/%6 records, %7/%8 bytes\n"
                       "Pending BMM anchors: %9/%10 records, %11/%12 bytes")
                        .arg(side_candidates,
                             side_candidate_limit,
                             NumberField(chain, "side_candidate_bytes"),
                             NumberField(chain, "side_candidate_bytes_limit"),
                             candidate_anchors,
                             candidate_anchor_limit,
                             NumberField(chain, "candidate_bmm_anchor_bytes"),
                             NumberField(chain, "candidate_bmm_anchor_bytes_limit"),
                             NumberField(chain, "pending_bmm_anchor_count"),
                             NumberField(chain, "pending_bmm_anchor_limit"),
                             NumberField(chain, "pending_bmm_anchor_bytes"),
                             NumberField(chain, "pending_bmm_anchor_bytes_limit"))};
                dag_item->setToolTip(
                    storage_tooltip + QStringLiteral("\n") +
                    tr("Pending block data: %1 distinct blocks")
                        .arg(pending_blocks));
            }
            if (chain_id == selected) m_table->selectRow(row);
        }
        m_table->setSortingEnabled(true);

        m_registry_summary->setText(
            tr("Main-chain registry at height %1 • root %2 • %n child chain(s)", nullptr, m_table->rowCount())
                .arg(NumberField(result, "height"), StringField(result, "root")));
        if (m_table->rowCount() > 0 && m_table->selectedItems().isEmpty()) {
            m_table->selectRow(0);
        }
    } catch (UniValue& error) {
        showRpcError(tr("Refresh child chains"), RpcErrorMessage(error));
    } catch (const std::exception& error) {
        showRpcError(tr("Refresh child chains"), QString::fromStdString(error.what()));
    }
    QApplication::restoreOverrideCursor();
    m_refresh_button->setEnabled(true);
    updateSelection();
}

QString ChildChainDialog::selectedChainId() const
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    return item ? item->data(CHAIN_ID_ROLE).toString() : QString{};
}

void ChildChainDialog::updateSelection()
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    if (!item) {
        m_load_button->setEnabled(false);
        m_unload_button->setEnabled(false);
        m_forget_button->setEnabled(false);
        m_add_button->setEnabled(false);
        m_add_peer_button->setEnabled(false);
        m_remove_peer_button->setEnabled(false);
        m_binds_button->setEnabled(false);
        m_network_button->setEnabled(false);
        m_network_button->setText(tr("Pause Network"));
        m_selection_summary->setText(tr("Select a child chain to manage its local runtime."));
        return;
    }

    const QString chain_id{item->data(CHAIN_ID_ROLE).toString()};
    const bool configured{item->data(CONFIGURED_ROLE).toBool()};
    const bool loaded{item->data(LOADED_ROLE).toBool()};
    const bool registry_found{item->data(REGISTRY_FOUND_ROLE).toBool()};
    const QString state{item->data(STATE_ROLE).toString()};
    const bool network_running{item->data(NETWORK_RUNNING_ROLE).toBool()};
    const bool network_active{item->data(NETWORK_ACTIVE_ROLE).toBool()};
    const QStringList added_nodes{item->data(ADDED_NODES_ROLE).toStringList()};
    const QStringList binds{item->data(BINDS_ROLE).toStringList()};
    m_load_button->setEnabled(configured && !loaded && state == QStringLiteral("configured"));
    m_unload_button->setEnabled(loaded);
    m_forget_button->setEnabled(configured && !loaded);
    m_add_button->setEnabled(registry_found && !configured && state == QStringLiteral("available"));
    m_add_peer_button->setEnabled(loaded && network_running);
    m_remove_peer_button->setEnabled(loaded && network_running && !added_nodes.isEmpty());
    m_binds_button->setEnabled(loaded && network_running);
    m_network_button->setEnabled(loaded && network_running);
    m_network_button->setText(network_active ? tr("Pause Network") : tr("Resume Network"));
    m_selection_summary->setText(
        tr("Chain ID: %1\nState: %2 • registry: %3 • local configuration: %4 • network: %5 • explicit peers: %6 • listen endpoints: %7")
            .arg(chain_id,
                 StateLabel(state),
                 registry_found ? tr("present") : tr("not present"),
                 configured ? tr("present") : tr("not present"),
                 !network_running ? tr("stopped") : network_active ? tr("active") : tr("paused"),
                 QString::number(added_nodes.size()),
                 QString::number(binds.size())));
}

void ChildChainDialog::addManifest()
{
    const QString expected_chain_id{selectedChainId()};
    if (expected_chain_id.isEmpty()) return;

    bool accepted{false};
    const QString text{QInputDialog::getMultiLineText(
        this,
        tr("Add Child Manifest"),
        tr("Paste a JSON object containing registration_anchor and manifest.\n"
           "The complete manifest will be validated against child chain %1 on the active main-chain registry.")
            .arg(expected_chain_id),
        QStringLiteral("{\n  \"registration_anchor\": {\"txid\": \"\", \"vout\": 0},\n  \"manifest\": {}\n}"),
        &accepted)};
    if (!accepted) return;

    UniValue input;
    if (!input.read(text.toStdString()) || !input.isObject()) {
        QMessageBox::warning(this, tr("Invalid Manifest"), tr("The supplied text is not a valid JSON object."));
        return;
    }
    const UniValue& anchor{input.find_value("registration_anchor")};
    const UniValue& manifest{input.find_value("manifest")};
    if (!anchor.isObject() || !manifest.isObject()) {
        QMessageBox::warning(
            this,
            tr("Invalid Manifest"),
            tr("The JSON object must contain registration_anchor and manifest objects."));
        return;
    }

    UniValue params{UniValue::VARR};
    params.push_back(anchor);
    params.push_back(manifest);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        const UniValue result{m_node.executeRpc("addchildchain", params, "")};
        const QString chain_id{StringField(result, "chain_id")};
        if (chain_id != expected_chain_id) {
            throw std::runtime_error{"addchildchain returned an unexpected chain_id"};
        }
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Add child manifest"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Add child manifest"), QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();
    refresh();
}

bool ChildChainDialog::runLifecycleCommand(const char* command, const QString& chain_id)
{
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    return runCommand(command, std::move(params));
}

bool ChildChainDialog::runCommand(const char* command, UniValue params)
{
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        m_node.executeRpc(command, params, "");
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(QString::fromLatin1(command), RpcErrorMessage(error));
        return false;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(QString::fromLatin1(command), QString::fromStdString(error.what()));
        return false;
    }
    QApplication::restoreOverrideCursor();
    refresh();
    return true;
}

void ChildChainDialog::addPeer()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty()) return;
    bool accepted{false};
    const QString endpoint{QInputDialog::getText(
        this,
        tr("Add Child Peer"),
        tr("Enter a child peer endpoint with an explicit port (host:port or [IPv6]:port):"),
        QLineEdit::Normal,
        {},
        &accepted).trimmed()};
    if (!accepted || endpoint.isEmpty()) return;
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    params.push_back(endpoint.toStdString());
    runCommand("addchildnode", std::move(params));
}

void ChildChainDialog::removePeer()
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    if (!item) return;
    const QString chain_id{item->data(CHAIN_ID_ROLE).toString()};
    const QStringList endpoints{item->data(ADDED_NODES_ROLE).toStringList()};
    if (chain_id.isEmpty() || endpoints.isEmpty()) return;
    bool accepted{false};
    const QString endpoint{QInputDialog::getItem(
        this,
        tr("Remove Child Peer"),
        tr("Select the persistent endpoint to disconnect and remove:"),
        endpoints,
        0,
        false,
        &accepted)};
    if (!accepted || endpoint.isEmpty()) return;
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    params.push_back(endpoint.toStdString());
    runCommand("removechildnode", std::move(params));
}

void ChildChainDialog::configureBinds()
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    if (!item) return;
    const QString chain_id{item->data(CHAIN_ID_ROLE).toString()};
    if (chain_id.isEmpty()) return;

    bool accepted{false};
    const QString text{QInputDialog::getMultiLineText(
        this,
        tr("Child Listen Endpoints"),
        tr("Enter one numeric endpoint per line with an explicit port.\n"
           "Leave the field empty to disable inbound connections for this child chain."),
        item->data(BINDS_ROLE).toStringList().join(QLatin1Char('\n')),
        &accepted)};
    if (!accepted) return;

    UniValue binds{UniValue::VARR};
    for (const QString& line : text.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QString endpoint{line.trimmed()};
        if (!endpoint.isEmpty()) binds.push_back(endpoint.toStdString());
    }
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    params.push_back(std::move(binds));
    runCommand("setchildnetworkbinds", std::move(params));
}

void ChildChainDialog::toggleNetwork()
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    if (!item) return;
    const QString chain_id{item->data(CHAIN_ID_ROLE).toString()};
    if (chain_id.isEmpty()) return;
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    params.push_back(!item->data(NETWORK_ACTIVE_ROLE).toBool());
    runCommand("setchildnetworkactive", std::move(params));
}

void ChildChainDialog::loadSelected()
{
    const QString chain_id{selectedChainId()};
    if (!chain_id.isEmpty()) runLifecycleCommand("loadchildchain", chain_id);
}

void ChildChainDialog::unloadSelected()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty()) return;
    if (QMessageBox::question(
            this,
            tr("Unload Child Chain"),
            tr("Stop the local runtime for child chain %1?\n\n"
               "Its manifest and all chain data will be preserved.")
                .arg(chain_id),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) == QMessageBox::Yes) {
        runLifecycleCommand("unloadchildchain", chain_id);
    }
}

void ChildChainDialog::forgetSelected()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty()) return;
    if (QMessageBox::warning(
            this,
            tr("Forget Child Chain"),
            tr("Remove child chain %1 from this node's local catalog?\n\n"
               "Existing chain data will remain on disk. The chain can be reopened later by adding the same "
               "manifest again.")
                .arg(chain_id),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) == QMessageBox::Yes) {
        runLifecycleCommand("forgetchildchain", chain_id);
    }
}

void ChildChainDialog::showRpcError(const QString& operation, const QString& message)
{
    QMessageBox::critical(this, tr("Child Chain Error"), tr("%1 failed:\n%2").arg(operation, message));
}
