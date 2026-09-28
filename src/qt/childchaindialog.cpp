// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/childchaindialog.h>

#include <core_io.h>
#include <interfaces/node.h>
#ifdef ENABLE_WALLET
#include <qt/bitcoinamountfield.h>
#include <qt/walletmodel.h>
#endif
#include <qt/guiutil.h>
#include <univalue.h>

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#ifdef ENABLE_WALLET
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSpinBox>
#include <QUrl>
#endif
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QVariant>

#include <cstdint>
#include <exception>
#include <limits>
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

uint64_t UnsignedField(const UniValue& object, const char* name)
{
    const UniValue& value{object.find_value(name)};
    return value.isNum() ? value.getInt<uint64_t>() : 0;
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
    m_discovery_button = actions->addButton(tr("Discovery…"), QDialogButtonBox::ActionRole);
    m_network_button = actions->addButton(tr("Pause Network"), QDialogButtonBox::ActionRole);
#ifdef ENABLE_WALLET
    m_migrate_button = actions->addButton(tr("Migrate…"), QDialogButtonBox::ActionRole);
    m_update_button = actions->addButton(tr("Update Metadata…"), QDialogButtonBox::ActionRole);
    m_retire_button = actions->addButton(tr("Retire…"), QDialogButtonBox::DestructiveRole);
    m_migrate_button->setObjectName(QStringLiteral("childChainMigrateButton"));
    m_update_button->setObjectName(QStringLiteral("childChainUpdateButton"));
    m_retire_button->setObjectName(QStringLiteral("childChainRetireButton"));
#endif
    m_add_peer_button->setObjectName(QStringLiteral("childChainAddPeerButton"));
    m_remove_peer_button->setObjectName(QStringLiteral("childChainRemovePeerButton"));
    m_binds_button->setObjectName(QStringLiteral("childChainBindsButton"));
    m_discovery_button->setObjectName(QStringLiteral("childChainDiscoveryButton"));
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
    connect(m_discovery_button, &QPushButton::clicked, this, &ChildChainDialog::configureDiscovery);
    connect(m_network_button, &QPushButton::clicked, this, &ChildChainDialog::toggleNetwork);
#ifdef ENABLE_WALLET
    connect(m_migrate_button, &QPushButton::clicked, this, &ChildChainDialog::migrateSelected);
    connect(m_update_button, &QPushButton::clicked, this, &ChildChainDialog::updateSelected);
    connect(m_retire_button, &QPushButton::clicked, this, &ChildChainDialog::retireSelected);
#endif
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
            const QString known_addresses{NumberField(chain, "known_addresses")};
            const QString rate_limited{
                NumberField(chain, "rate_limited_block_requests")};
            const QStringList added_nodes{StringArrayField(chain, "added_nodes")};
            const QStringList binds{StringArrayField(chain, "binds")};
            const bool discovery{BoolField(chain, "discovery_enabled")};
            const QStringList bootstrap_nodes{
                StringArrayField(chain, "bootstrap_nodes")};
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
                    : tr("%1 connected • %2 authenticated • %3 known")
                          .arg(connections, handshaken, known_addresses)};

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
            status_item->setData(DISCOVERY_ROLE, discovery);
            status_item->setData(BOOTSTRAP_NODES_ROLE, bootstrap_nodes);
            status_item->setData(KNOWN_ADDRESSES_ROLE, known_addresses);
            status_item->setData(
                RATE_LIMITED_REQUESTS_ROLE, rate_limited);
            status_item->setData(SUPPORTED_ROLE, BoolField(chain, "supported"));
            status_item->setData(METADATA_HASH_ROLE, StringField(chain, "metadata_hash"));
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
            const QString discovery_tooltip{!discovery
                ? tr("Automatic child peer discovery disabled")
                : bootstrap_nodes.isEmpty()
                    ? tr("Automatic child peer discovery enabled using the isolated peer store")
                    : tr("Automatic child peer discovery enabled\nBootstrap endpoints:\n%1")
                          .arg(bootstrap_nodes.join(QLatin1Char('\n')))};
            network_item->setToolTip(
                outbound_tooltip + QStringLiteral("\n\n") + inbound_tooltip +
                QStringLiteral("\n\n") + discovery_tooltip +
                QStringLiteral("\n\n") +
                tr("Known isolated peer-store addresses: %1")
                    .arg(known_addresses) +
                QStringLiteral("\n") +
                tr("Rate-limited block requests: %1").arg(rate_limited));
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

        const uint64_t upload_bytes{
            UnsignedField(result, "aggregate_upload_bytes_sent")};
        const uint64_t upload_target{
            UnsignedField(result, "aggregate_upload_target")};
        QString upload_summary{
            upload_target == 0
                ? tr("%1 (unlimited)").arg(GUIUtil::formatBytes(upload_bytes))
                : tr("%1 of %2").arg(GUIUtil::formatBytes(upload_bytes),
                                      GUIUtil::formatBytes(upload_target))};
        if (BoolField(result, "aggregate_upload_target_reached")) {
            upload_summary += tr(" (limit reached)");
        }
        m_registry_summary->setText(
            tr("Main-chain registry at height %1 • root %2 • %3/%4 child runtime(s) loaded • child block upload %5 • %n registered child chain(s)", nullptr, m_table->rowCount())
                .arg(NumberField(result, "height"),
                     StringField(result, "root"),
                     NumberField(result, "loaded"),
                     NumberField(result, "max_loaded"),
                     upload_summary));
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
        m_discovery_button->setEnabled(false);
        m_network_button->setEnabled(false);
#ifdef ENABLE_WALLET
        m_migrate_button->setEnabled(false);
        m_update_button->setEnabled(false);
        m_retire_button->setEnabled(false);
#endif
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
    const bool discovery{item->data(DISCOVERY_ROLE).toBool()};
    const QStringList bootstrap_nodes{
        item->data(BOOTSTRAP_NODES_ROLE).toStringList()};
    const QString rate_limited{
        item->data(RATE_LIMITED_REQUESTS_ROLE).toString()};
    const QString known_addresses{
        item->data(KNOWN_ADDRESSES_ROLE).toString()};
    const bool supported{item->data(SUPPORTED_ROLE).toBool()};
    m_load_button->setEnabled(configured && !loaded && state == QStringLiteral("configured"));
    m_unload_button->setEnabled(loaded);
    m_forget_button->setEnabled(configured && !loaded);
    m_add_button->setEnabled(registry_found && !configured && state == QStringLiteral("available"));
    m_add_peer_button->setEnabled(loaded && network_running);
    m_remove_peer_button->setEnabled(loaded && network_running && !added_nodes.isEmpty());
    m_binds_button->setEnabled(loaded && network_running);
    m_discovery_button->setEnabled(loaded && network_running);
    m_network_button->setEnabled(loaded && network_running);
#ifdef ENABLE_WALLET
    const bool active_registry_record{
        m_wallet_model && registry_found &&
        (state == QStringLiteral("available") ||
         state == QStringLiteral("configured") ||
         state == QStringLiteral("loaded"))};
    m_migrate_button->setEnabled(
        active_registry_record && supported);
    m_update_button->setEnabled(active_registry_record);
    m_retire_button->setEnabled(active_registry_record);
#endif
    m_network_button->setText(network_active ? tr("Pause Network") : tr("Resume Network"));
    m_selection_summary->setText(
        tr("Chain ID: %1\nState: %2 • registry: %3 • local configuration: %4 • network: %5 • explicit peers: %6 • listen endpoints: %7 • discovery: %8 (%9 bootstrap, %10 known) • rate-limited block requests: %11")
            .arg(chain_id,
                 StateLabel(state),
                 registry_found ? tr("present") : tr("not present"),
                 configured ? tr("present") : tr("not present"),
                 !network_running ? tr("stopped") : network_active ? tr("active") : tr("paused"),
                 QString::number(added_nodes.size()),
                 QString::number(binds.size()),
                 discovery ? tr("enabled") : tr("disabled"),
                 QString::number(bootstrap_nodes.size()),
                 known_addresses,
                 rate_limited));
}

#ifdef ENABLE_WALLET
void ChildChainDialog::setWalletModel(WalletModel* wallet_model)
{
    m_wallet_model = wallet_model;
    updateSelection();
}

std::string ChildChainDialog::walletUri() const
{
    if (!m_wallet_model || m_wallet_model->getWalletName().isEmpty()) return {};
    const QByteArray encoded_name{
        QUrl::toPercentEncoding(m_wallet_model->getWalletName())};
    return "/wallet/" +
        std::string{encoded_name.constData(),
                    static_cast<size_t>(encoded_name.size())};
}

void ChildChainDialog::submitRegistryOperation(const char* operation,
                                               const QString& chain_id,
                                               UniValue parameters)
{
    if (!m_wallet_model) return;
    const QPointer<WalletModel> wallet_model{m_wallet_model};
    const std::string wallet_uri{walletUri()};

    UniValue create_params{UniValue::VARR};
    create_params.push_back(operation);
    create_params.push_back(std::move(parameters));

    UniValue created;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        created = m_node.executeRpc(
            "walletcreatechainregistrypsbt", create_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create registry operation"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create registry operation"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const QString operation_name{QString::fromLatin1(operation)};
    const UniValue& created_operation{created.find_value("operation")};
    const UniValue& created_chain{created.find_value("chain_id")};
    const UniValue& psbt{created.find_value("psbt")};
    const UniValue& fee{created.find_value("fee")};
    if (!created_operation.isStr() ||
        QString::fromStdString(created_operation.get_str()) != operation_name ||
        !created_chain.isStr() ||
        QString::fromStdString(created_chain.get_str()) != chain_id ||
        !psbt.isStr() || !fee.isNum()) {
        showRpcError(tr("Create registry operation"),
                     tr("The wallet returned an invalid registry proposal."));
        return;
    }

    const bool retiring{operation_name == QStringLiteral("retire")};
    QMessageBox confirmation{
        QMessageBox::Warning,
        retiring ? tr("Confirm Permanent Retirement")
                 : tr("Confirm Metadata Update"),
        retiring
            ? tr("Permanently retire child chain %1?\n\nNew deposits and anchors will stop after confirmation on the main chain. Protocol v1 has no operation that reactivates a retired chain.\n\nMain-chain fee: %2 KNE")
                  .arg(chain_id, QString::fromStdString(fee.getValStr()))
            : tr("Update the metadata commitment and rotate the control output for child chain %1?\n\nMain-chain fee: %2 KNE")
                  .arg(chain_id, QString::fromStdString(fee.getValStr())),
        QMessageBox::Yes | QMessageBox::Cancel,
        this};
    confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) return;

    if (!wallet_model) {
        showRpcError(tr("Submit registry operation"),
                     tr("The selected wallet is no longer available."));
        return;
    }
    WalletModel::UnlockContext unlock_context{wallet_model->requestUnlock()};
    if (!unlock_context.isValid()) return;

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(psbt.get_str());
    UniValue submitted;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        submitted = m_node.executeRpc(
            "walletsubmitchainregistrypsbt", submit_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Submit registry operation"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Submit registry operation"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& submitted_operation{submitted.find_value("operation")};
    const UniValue& submitted_chain{submitted.find_value("chain_id")};
    const UniValue& txid{submitted.find_value("txid")};
    const UniValue& submitted_fee{submitted.find_value("fee")};
    const UniValue& registration_burn{submitted.find_value("registration_burn")};
    if (!submitted_operation.isStr() ||
        QString::fromStdString(submitted_operation.get_str()) != operation_name ||
        !submitted_chain.isStr() ||
        QString::fromStdString(submitted_chain.get_str()) != chain_id ||
        !txid.isStr() || !submitted_fee.isNum() ||
        submitted_fee.getValStr() != fee.getValStr() ||
        !registration_burn.isNum() ||
        registration_burn.getValStr() != ValueFromAmount(0).getValStr()) {
        showRpcError(tr("Submit registry operation"),
                     tr("The wallet returned an invalid registry result."));
        return;
    }

    QMessageBox::information(
        this,
        retiring ? tr("Retirement Submitted") : tr("Update Submitted"),
        tr("The registry operation was broadcast.\n\nTransaction: %1\nChild chain: %2")
            .arg(QString::fromStdString(txid.get_str()), chain_id));
    refresh();
}

void ChildChainDialog::updateSelected()
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    const QString chain_id{selectedChainId()};
    if (!item || chain_id.isEmpty() || !m_wallet_model) return;

    bool accepted{false};
    const QString metadata_hash{QInputDialog::getText(
        this,
        tr("Update Child Metadata"),
        tr("New metadata hash (32-byte hexadecimal commitment):"),
        QLineEdit::Normal,
        item->data(METADATA_HASH_ROLE).toString(),
        &accepted).trimmed()};
    if (!accepted) return;
    if (!QRegularExpression{QStringLiteral("^[0-9A-Fa-f]{64}$")}
             .match(metadata_hash)
             .hasMatch()) {
        QMessageBox::warning(
            this,
            tr("Invalid Metadata Hash"),
            tr("Enter exactly 32 bytes (64 hexadecimal characters)."));
        return;
    }

    UniValue address;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        address = m_node.executeRpc(
            "getnewaddress", UniValue{UniValue::VARR}, walletUri());
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create successor control"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create successor control"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();
    if (!address.isStr()) {
        showRpcError(tr("Create successor control"),
                     tr("The wallet returned an invalid control address."));
        return;
    }

    UniValue parameters{UniValue::VOBJ};
    parameters.pushKV("chain_id", chain_id.toStdString());
    parameters.pushKV("metadata_hash", metadata_hash.toStdString());
    parameters.pushKV("control_address", address.get_str());
    submitRegistryOperation("update", chain_id, std::move(parameters));
}

void ChildChainDialog::retireSelected()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty() || !m_wallet_model) return;
    UniValue parameters{UniValue::VOBJ};
    parameters.pushKV("chain_id", chain_id.toStdString());
    submitRegistryOperation("retire", chain_id, std::move(parameters));
}

void ChildChainDialog::migrateSelected()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty() || !m_wallet_model) return;
    const QPointer<WalletModel> wallet_model{m_wallet_model};
    const std::string wallet_uri{walletUri()};

    QDialog input_dialog{this};
    input_dialog.setWindowTitle(tr("Migrate KNE to Child Chain"));
    auto* layout = new QVBoxLayout{&input_dialog};
    auto* warning = new QLabel{
        tr("This transfer is irreversible. Main-chain KNE will be permanently destroyed and cannot return from the child chain."),
        &input_dialog};
    warning->setWordWrap(true);
    layout->addWidget(warning);

    auto* form = new QFormLayout;
    auto* chain = new QLineEdit{chain_id, &input_dialog};
    chain->setReadOnly(true);
    auto* recipient_type = new QSpinBox{&input_dialog};
    recipient_type->setRange(1, std::numeric_limits<uint16_t>::max());
    recipient_type->setValue(1);
    recipient_type->setReadOnly(true);
    recipient_type->setToolTip(
        tr("Reference child template v1 uses recipient type 1 for P2TR output keys."));
    auto* recipient = new QLineEdit{&input_dialog};
    recipient->setValidator(new QRegularExpressionValidator{
        QRegularExpression{QStringLiteral("[0-9A-Fa-f]{64}")}, recipient});
    recipient->setPlaceholderText(tr("32-byte P2TR output key in hexadecimal"));
    auto* amount = new BitcoinAmountField{&input_dialog};
    amount->SetAllowEmpty(false);
    amount->SetMinValue(1);
    amount->SetMaxValue(MAX_MONEY);
    form->addRow(tr("Child chain:"), chain);
    form->addRow(tr("Recipient type:"), recipient_type);
    form->addRow(tr("Recipient bytes:"), recipient);
    form->addRow(tr("Amount:"), amount);
    layout->addLayout(form);

    auto* buttons = new QDialogButtonBox{
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &input_dialog};
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Review Migration"));
    connect(buttons, &QDialogButtonBox::accepted, &input_dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &input_dialog, &QDialog::reject);
    layout->addWidget(buttons);
    if (input_dialog.exec() != QDialog::Accepted) return;
    if (!recipient->hasAcceptableInput()) {
        QMessageBox::warning(
            this,
            tr("Invalid Recipient"),
            tr("Enter exactly 32 bytes (64 hexadecimal characters) for the child P2TR output key."));
        return;
    }
    if (!amount->validate() || amount->value() <= 0) {
        QMessageBox::warning(this, tr("Invalid Amount"), tr("Enter a positive migration amount."));
        return;
    }

    UniValue create_params{UniValue::VARR};
    create_params.push_back(chain_id.toStdString());
    create_params.push_back(recipient_type->value());
    create_params.push_back(recipient->text().trimmed().toStdString());
    create_params.push_back(ValueFromAmount(amount->value()));

    UniValue created;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        created = m_node.executeRpc(
            "walletcreatefundchainpsbt", create_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create child migration"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create child migration"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& created_chain{created.find_value("chain_id")};
    const UniValue& psbt{created.find_value("psbt")};
    const UniValue& created_amount{created.find_value("amount")};
    const UniValue& fee{created.find_value("fee")};
    const UniValue& irreversible{created.find_value("irreversible")};
    const UniValue& created_recipient_type{created.find_value("recipient_type")};
    const UniValue& created_recipient{created.find_value("recipient")};
    if (!created_chain.isStr() ||
        QString::fromStdString(created_chain.get_str()) != chain_id ||
        !psbt.isStr() || !created_amount.isNum() || !fee.isNum() ||
        !irreversible.isBool() || !irreversible.get_bool() ||
        !created_recipient_type.isNum() ||
        created_recipient_type.getInt<int>() != recipient_type->value() ||
        !created_recipient.isStr() ||
        QString::fromStdString(created_recipient.get_str()).compare(
            recipient->text().trimmed(), Qt::CaseInsensitive) != 0) {
        showRpcError(tr("Create child migration"),
                     tr("The wallet returned an invalid migration proposal."));
        return;
    }

    QMessageBox confirmation{
        QMessageBox::Warning,
        tr("Confirm Irreversible Migration"),
        tr("Permanently destroy %1 KNE on the main chain and migrate it to child chain %2?\n\nRecipient type: %3\nRecipient: %4\nMain-chain fee: %5 KNE\n\nThere is no child-to-main withdrawal path.")
            .arg(QString::fromStdString(created_amount.getValStr()),
                 chain_id,
                 QString::number(recipient_type->value()),
                 QString::fromStdString(created_recipient.get_str()),
                 QString::fromStdString(fee.getValStr())),
        QMessageBox::Yes | QMessageBox::Cancel,
        this};
    confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) return;

    if (!wallet_model) {
        showRpcError(tr("Submit child migration"),
                     tr("The selected wallet is no longer available."));
        return;
    }
    WalletModel::UnlockContext unlock_context{wallet_model->requestUnlock()};
    if (!unlock_context.isValid()) return;

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(psbt.get_str());
    submit_params.push_back(true);
    submit_params.push_back(created_amount);
    UniValue submitted;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        submitted = m_node.executeRpc(
            "walletsubmitfundchainpsbt", submit_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Submit child migration"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Submit child migration"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& submitted_chain{submitted.find_value("chain_id")};
    const UniValue& txid{submitted.find_value("txid")};
    const UniValue& deposit_id{submitted.find_value("deposit_id")};
    const UniValue& submitted_recipient_type{submitted.find_value("recipient_type")};
    const UniValue& submitted_recipient{submitted.find_value("recipient")};
    const UniValue& submitted_amount{submitted.find_value("amount")};
    const UniValue& submitted_irreversible{submitted.find_value("irreversible")};
    if (!submitted_chain.isStr() ||
        QString::fromStdString(submitted_chain.get_str()) != chain_id ||
        !txid.isStr() || !deposit_id.isStr() ||
        !submitted_recipient_type.isNum() ||
        submitted_recipient_type.getInt<int>() != recipient_type->value() ||
        !submitted_recipient.isStr() ||
        submitted_recipient.get_str() != created_recipient.get_str() ||
        !submitted_amount.isNum() ||
        submitted_amount.getValStr() != created_amount.getValStr() ||
        !submitted_irreversible.isBool() ||
        !submitted_irreversible.get_bool()) {
        showRpcError(tr("Submit child migration"),
                     tr("The wallet returned an invalid migration result."));
        return;
    }
    QMessageBox::information(
        this,
        tr("Migration Submitted"),
        tr("The irreversible migration was broadcast.\n\nTransaction: %1\nDeposit ID: %2")
            .arg(QString::fromStdString(txid.get_str()),
                 QString::fromStdString(deposit_id.get_str())));
}
#endif

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

void ChildChainDialog::configureDiscovery()
{
    const int row{m_table->currentRow()};
    const QTableWidgetItem* item{row >= 0 ? m_table->item(row, STATUS) : nullptr};
    if (!item) return;
    const QString chain_id{item->data(CHAIN_ID_ROLE).toString()};
    if (chain_id.isEmpty()) return;

    QDialog dialog{this};
    dialog.setWindowTitle(tr("Child Peer Discovery"));
    auto* enabled = new QCheckBox{tr("Enable bounded automatic outbound connections"), &dialog};
    enabled->setChecked(item->data(DISCOVERY_ROLE).toBool());
    auto* endpoints = new QPlainTextEdit{&dialog};
    endpoints->setPlainText(
        item->data(BOOTSTRAP_NODES_ROLE).toStringList().join(QLatin1Char('\n')));
    endpoints->setPlaceholderText(tr("One numeric address and explicit port per line"));
    auto* form = new QFormLayout;
    form->addRow(enabled);
    form->addRow(tr("Bootstrap endpoints:"), endpoints);
    auto* buttons = new QDialogButtonBox{
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog};
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    auto* layout = new QVBoxLayout{&dialog};
    layout->addLayout(form);
    auto* explanation = new QLabel{
        tr("Bootstrap names are intentionally not resolved: use numeric IPv4 or IPv6 endpoints. Discovery remains confined to this child chain and never loads another runtime."),
        &dialog};
    explanation->setWordWrap(true);
    layout->addWidget(explanation);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted) return;

    UniValue bootstrap{UniValue::VARR};
    for (const QString& line :
         endpoints->toPlainText().split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QString endpoint{line.trimmed()};
        if (!endpoint.isEmpty()) bootstrap.push_back(endpoint.toStdString());
    }
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    params.push_back(enabled->isChecked());
    params.push_back(std::move(bootstrap));
    runCommand("setchildnetworkdiscovery", std::move(params));
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
