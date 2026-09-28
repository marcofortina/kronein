// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/childchaindialog.h>

#include <core_io.h>
#include <interfaces/node.h>
#ifdef ENABLE_WALLET
#include <chainregistry/child_template.h>
#include <qt/bitcoinamountfield.h>
#include <qt/walletmodel.h>
#endif
#include <qt/guiutil.h>
#include <univalue.h>

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#ifdef ENABLE_WALLET
#include <QSaveFile>
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

QString BmmHealthLabel(const QString& health)
{
    if (health == QStringLiteral("idle")) return ChildChainDialog::tr("Idle");
    if (health == QStringLiteral("awaiting_anchor")) return ChildChainDialog::tr("Awaiting BMM anchor");
    if (health == QStringLiteral("anchor_ready")) return ChildChainDialog::tr("Anchor ready");
    if (health == QStringLiteral("awaiting_block_data")) return ChildChainDialog::tr("Awaiting child block data");
    if (health == QStringLiteral("anchored")) return ChildChainDialog::tr("Anchored");
    if (health == QStringLiteral("safe_halt")) return ChildChainDialog::tr("Safe halt");
    if (health == QStringLiteral("failed")) return ChildChainDialog::tr("Failed");
    return health;
}

#ifdef ENABLE_WALLET
QString DepositStatusLabel(const QString& status)
{
    if (status == QStringLiteral("confirmed")) return ChildChainDialog::tr("Confirmed");
    if (status == QStringLiteral("mempool")) return ChildChainDialog::tr("In mempool");
    if (status == QStringLiteral("inactive")) return ChildChainDialog::tr("Inactive");
    if (status == QStringLiteral("abandoned")) return ChildChainDialog::tr("Abandoned");
    if (status == QStringLiteral("conflicted")) return ChildChainDialog::tr("Conflicted");
    return status;
}

QString TransactionCategoryLabel(const QString& category)
{
    if (category == QStringLiteral("send")) return ChildChainDialog::tr("Sent");
    if (category == QStringLiteral("receive")) return ChildChainDialog::tr("Received");
    if (category == QStringLiteral("generate")) return ChildChainDialog::tr("Mined");
    if (category == QStringLiteral("immature")) return ChildChainDialog::tr("Immature");
    return {};
}
#endif

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
    m_bmm_button = actions->addButton(tr("BMM…"), QDialogButtonBox::ActionRole);
#ifdef ENABLE_WALLET
    m_register_button = actions->addButton(tr("Register…"), QDialogButtonBox::ActionRole);
    m_balance_button = actions->addButton(tr("Balance…"), QDialogButtonBox::ActionRole);
    m_activity_button = actions->addButton(tr("Activity…"), QDialogButtonBox::ActionRole);
    m_deposits_button = actions->addButton(tr("Deposits…"), QDialogButtonBox::ActionRole);
    m_migrate_button = actions->addButton(tr("Migrate…"), QDialogButtonBox::ActionRole);
    m_update_button = actions->addButton(tr("Update Metadata…"), QDialogButtonBox::ActionRole);
    m_retire_button = actions->addButton(tr("Retire…"), QDialogButtonBox::DestructiveRole);
    m_register_button->setObjectName(QStringLiteral("childChainRegisterButton"));
    m_balance_button->setObjectName(QStringLiteral("childChainBalanceButton"));
    m_balance_button->setToolTip(
        tr("Scan the loaded child UTXO set for recipients owned by the selected wallet."));
    m_activity_button->setObjectName(QStringLiteral("childChainActivityButton"));
    m_activity_button->setToolTip(
        tr("Show confirmed and pending wallet activity on the loaded child chain."));
    m_deposits_button->setObjectName(QStringLiteral("childChainDepositsButton"));
    m_migrate_button->setObjectName(QStringLiteral("childChainMigrateButton"));
    m_update_button->setObjectName(QStringLiteral("childChainUpdateButton"));
    m_retire_button->setObjectName(QStringLiteral("childChainRetireButton"));
#endif
    m_add_peer_button->setObjectName(QStringLiteral("childChainAddPeerButton"));
    m_remove_peer_button->setObjectName(QStringLiteral("childChainRemovePeerButton"));
    m_binds_button->setObjectName(QStringLiteral("childChainBindsButton"));
    m_discovery_button->setObjectName(QStringLiteral("childChainDiscoveryButton"));
    m_network_button->setObjectName(QStringLiteral("childChainNetworkButton"));
    m_bmm_button->setObjectName(QStringLiteral("childChainBmmButton"));
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
    connect(m_bmm_button, &QPushButton::clicked, this, &ChildChainDialog::manageBmm);
#ifdef ENABLE_WALLET
    connect(m_register_button, &QPushButton::clicked, this, &ChildChainDialog::registerChildChain);
    connect(m_balance_button, &QPushButton::clicked, this, &ChildChainDialog::showBalance);
    connect(m_activity_button, &QPushButton::clicked, this, &ChildChainDialog::showActivity);
    connect(m_deposits_button, &QPushButton::clicked, this, &ChildChainDialog::showDeposits);
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
            const QString local_proposals{NumberField(chain, "local_proposal_count")};
            const QString local_proposal_limit{NumberField(chain, "local_proposal_limit")};
            const QString dag_usage{loaded
                ? tr("%1 proposals • %2 pending • %3/%4 candidates • %5/%6 anchors")
                      .arg(local_proposals,
                           pending_blocks,
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
                    tr("Local proposals: %1/%2 records, %3/%4 bytes\n"
                       "Side candidates: %5/%6 records, %7/%8 bytes\n"
                       "Candidate BMM anchors: %9/%10 records, %11/%12 bytes\n"
                       "Pending BMM anchors: %13/%14 records, %15/%16 bytes")
                        .arg(local_proposals,
                             local_proposal_limit,
                             NumberField(chain, "local_proposal_bytes"),
                             NumberField(chain, "local_proposal_bytes_limit"),
                             side_candidates,
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
        m_bmm_button->setEnabled(false);
#ifdef ENABLE_WALLET
        m_register_button->setEnabled(m_wallet_model);
        m_balance_button->setEnabled(false);
        m_activity_button->setEnabled(false);
        m_deposits_button->setEnabled(false);
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
    m_bmm_button->setEnabled(loaded && supported);
#ifdef ENABLE_WALLET
    m_register_button->setEnabled(m_wallet_model);
    m_balance_button->setEnabled(m_wallet_model && loaded && supported);
    m_activity_button->setEnabled(m_wallet_model && loaded && supported);
    m_deposits_button->setEnabled(m_wallet_model);
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

void ChildChainDialog::manageBmm()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty()) return;

    const QString status_action{tr("View operational status")};
    const QString build_action{tr("Build and anchor an import block")};
    const QString activate_action{tr("Activate a stored confirmed proposal")};
    QStringList actions{status_action};
#ifdef ENABLE_WALLET
    if (m_wallet_model) actions.push_back(build_action);
#endif
    actions.push_back(activate_action);
    bool accepted{false};
    const QString action{QInputDialog::getItem(
        this,
        tr("Child BMM Workflow"),
        tr("Select an operation for child chain %1:").arg(chain_id),
        actions,
        0,
        false,
        &accepted)};
    if (!accepted || action.isEmpty()) return;

    if (action == status_action) {
        showBmmStatus(chain_id);
        return;
    }
#ifdef ENABLE_WALLET
    if (m_wallet_model && action == build_action) {
        createBmmProposal(chain_id);
        return;
    }
#endif
    activateBmmProposal(chain_id);
}

void ChildChainDialog::showBmmStatus(const QString& chain_id)
{
    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    UniValue status;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        status = m_node.executeRpc("getchildbmmstatus", params, "");
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Child BMM status"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Child BMM status"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& pending{status.find_value("pending_blocks")};
    const UniValue& proposals{status.find_value("proposals")};
    if (!status.isObject() || !pending.isArray() || !proposals.isArray() ||
        StringField(status, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0) {
        showRpcError(tr("Child BMM status"),
                     tr("The node returned an invalid BMM status snapshot."));
        return;
    }

    QDialog dialog{this};
    dialog.setWindowTitle(tr("Child BMM Operational Status"));
    dialog.setMinimumSize(900, 580);
    auto* layout = new QVBoxLayout{&dialog};
    auto* summary = new QLabel{
        tr("Health: %1\n"
           "Child: height %2 • tip %3\n"
           "Main: height %4 • tip %5\n"
           "Canonical anchors: %6 • tip anchor: %7\n"
           "Local proposals: %8 (%9 waiting, %10 anchored) • pending block data: %11 (%12 anchors)\n"
           "Competing DAG: %13 blocks / %14 anchors")
            .arg(BmmHealthLabel(StringField(status, "health")),
                 NumberField(status, "child_height"),
                 StringField(status, "bestblockhash"),
                 NumberField(status, "main_height"),
                 StringField(status, "main_bestblockhash"),
                 NumberField(status, "canonical_anchor_count"),
                 BoolField(status, "has_tip_anchor")
                     ? tr("%1 at main height %2 (%3 confirmations)")
                           .arg(StringField(status, "tip_anchor_main_block_hash"),
                                NumberField(status, "tip_anchor_main_height"),
                                NumberField(status, "tip_anchor_confirmations"))
                     : tr("none (virtual genesis)"),
                 NumberField(status, "proposal_count"),
                 NumberField(status, "proposals_without_anchor"),
                 NumberField(status, "proposals_with_anchor"),
                 NumberField(status, "pending_block_count"),
                 NumberField(status, "pending_anchor_count"),
                 NumberField(status, "side_candidate_count"),
                 NumberField(status, "candidate_anchor_count")),
        &dialog};
    summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summary->setWordWrap(true);
    layout->addWidget(summary);

    QStringList details;
    if (!pending.empty()) {
        details.push_back(tr("Pending child block data:"));
        for (const UniValue& block : pending.getValues()) {
            details.push_back(
                tr("  %1 — %2 anchor(s), main heights %3–%4")
                    .arg(StringField(block, "blockhash"),
                         NumberField(block, "anchor_count"),
                         NumberField(block, "oldest_anchor_height"),
                         NumberField(block, "newest_anchor_height")));
        }
    }
    if (!proposals.empty()) {
        if (!details.isEmpty()) details.push_back(QString{});
        details.push_back(tr("Durable local proposals:"));
        for (const UniValue& proposal : proposals.getValues()) {
            details.push_back(
                tr("  %1 — parent %2 — %3 bytes — %4")
                    .arg(StringField(proposal, "blockhash"),
                         StringField(proposal, "previousblockhash"),
                         NumberField(proposal, "size"),
                         BoolField(proposal, "anchor_available")
                             ? tr("authenticated anchor ready")
                             : tr("waiting for anchor")));
        }
    }
    if (details.isEmpty()) {
        details.push_back(tr("No pending BMM work is queued for this child chain."));
    }
    auto* detail_view = new QPlainTextEdit{details.join(QLatin1Char('\n')), &dialog};
    detail_view->setReadOnly(true);
    detail_view->setLineWrapMode(QPlainTextEdit::NoWrap);
    layout->addWidget(detail_view, 1);
    auto* buttons = new QDialogButtonBox{QDialogButtonBox::Close, &dialog};
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    dialog.exec();
}

void ChildChainDialog::activateBmmProposal(const QString& chain_id)
{
    UniValue list_params{UniValue::VARR};
    list_params.push_back(chain_id.toStdString());
    UniValue stored;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        stored = m_node.executeRpc("listchildproposals", list_params, "");
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List child proposals"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List child proposals"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& proposals{stored.find_value("proposals")};
    if (!stored.isObject() || !proposals.isArray()) {
        showRpcError(
            tr("List child proposals"),
            tr("The node returned an invalid child proposal list."));
        return;
    }
    if (proposals.empty()) {
        QMessageBox::information(
            this,
            tr("No Stored Child Proposals"),
            tr("This child chain has no local block proposal waiting for a BMM anchor."));
        return;
    }

    QDialog dialog{this};
    dialog.setWindowTitle(tr("Activate Confirmed Child Proposal"));
    dialog.setMinimumSize(850, 300);
    auto* layout = new QVBoxLayout{&dialog};
    auto* explanation = new QLabel{
        tr("Select a durable local proposal and enter the active main-chain block containing its confirmed anchor. The node will reconstruct and verify the KBPR proof before validating the stored child block."),
        &dialog};
    explanation->setWordWrap(true);
    layout->addWidget(explanation);
    auto* form = new QFormLayout;
    auto* chain = new QLineEdit{chain_id, &dialog};
    chain->setReadOnly(true);
    auto* proposal_selector = new QComboBox{&dialog};
    for (const UniValue& proposal : proposals.getValues()) {
        const QString block_hash{StringField(proposal, "blockhash")};
        if (!QRegularExpression{QStringLiteral("^[0-9A-Fa-f]{64}$")}
                 .match(block_hash).hasMatch()) {
            continue;
        }
        const QString status{BoolField(proposal, "anchor_available")
            ? tr("anchor staged")
            : tr("awaiting confirmation")};
        proposal_selector->addItem(
            tr("%1 — %2 — %3 bytes")
                .arg(block_hash, status, NumberField(proposal, "size")),
            block_hash);
    }
    if (proposal_selector->count() == 0) {
        showRpcError(
            tr("List child proposals"),
            tr("The node returned no valid child proposal identifiers."));
        return;
    }
    auto* main_block_hash = new QLineEdit{&dialog};
    main_block_hash->setValidator(new QRegularExpressionValidator{
        QRegularExpression{QStringLiteral("[0-9A-Fa-f]{64}")},
        main_block_hash});
    main_block_hash->setPlaceholderText(
        tr("32-byte active main-chain block hash"));
    form->addRow(tr("Child chain:"), chain);
    form->addRow(tr("Stored proposal:"), proposal_selector);
    form->addRow(tr("Main anchor block:"), main_block_hash);
    layout->addLayout(form);
    auto* buttons = new QDialogButtonBox{
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog};
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Verify and Activate"));
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted) return;
    if (!main_block_hash->hasAcceptableInput()) {
        QMessageBox::warning(
            this,
            tr("Invalid Main Block Hash"),
            tr("Enter exactly 32 bytes (64 hexadecimal characters) for the main-chain anchor block."));
        return;
    }

    const QString child_block_hash{
        proposal_selector->currentData().toString()};
    const QRegularExpression hex_bytes{
        QStringLiteral("^(?:[0-9A-Fa-f]{2})+$")};

    UniValue proof_params{UniValue::VARR};
    proof_params.push_back(chain_id.toStdString());
    proof_params.push_back(main_block_hash->text().trimmed().toStdString());
    UniValue proof;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        proof = m_node.executeRpc("getbmmanchorproof", proof_params, "");
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Verify BMM anchor"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Verify BMM anchor"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const QString proof_hex{StringField(proof, "proof")};
    if (StringField(proof, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0 ||
        StringField(proof, "child_block_hash").compare(
            child_block_hash, Qt::CaseInsensitive) != 0 ||
        StringField(proof, "main_block_hash").compare(
            main_block_hash->text().trimmed(), Qt::CaseInsensitive) != 0 ||
        !hex_bytes.match(proof_hex).hasMatch()) {
        showRpcError(
            tr("Verify BMM anchor"),
            tr("The verified main-chain anchor does not commit to this proposal."));
        return;
    }

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(chain_id.toStdString());
    submit_params.push_back(child_block_hash.toStdString());
    submit_params.push_back(proof_hex.toStdString());
    UniValue submitted;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        submitted = m_node.executeRpc(
            "submitchildproposal", submit_params, "");
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Activate child proposal"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Activate child proposal"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    if (!BoolField(submitted, "accepted") ||
        StringField(submitted, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0 ||
        StringField(submitted, "blockhash").compare(
            child_block_hash, Qt::CaseInsensitive) != 0) {
        showRpcError(
            tr("Activate child proposal"),
            tr("The node returned an invalid child activation result."));
        return;
    }
    QMessageBox::information(
        this,
        tr("Child Block Activated"),
        tr("Child block %1 was validated and submitted.\n\nActive child tip: %2")
            .arg(child_block_hash, StringField(submitted, "bestblockhash")));
    refresh();
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

void ChildChainDialog::createBmmProposal(const QString& chain_id)
{
    if (!m_wallet_model) return;
    const QPointer<WalletModel> wallet_model{m_wallet_model};
    const std::string wallet_uri{walletUri()};

    QDialog input_dialog{this};
    input_dialog.setWindowTitle(tr("Build and Anchor Child Import Block"));
    input_dialog.setMinimumSize(850, 520);
    auto* layout = new QVBoxLayout{&input_dialog};
    auto* explanation = new QLabel{
        tr("Paste one mature KDPR deposit proof per line. The node will authenticate every proof, build and contextually validate a child block, then create a main-chain KBMM security-bid transaction."),
        &input_dialog};
    explanation->setWordWrap(true);
    layout->addWidget(explanation);
    auto* form = new QFormLayout;
    auto* chain = new QLineEdit{chain_id, &input_dialog};
    chain->setReadOnly(true);
    auto* fee_rate = new QSpinBox{&input_dialog};
    fee_rate->setRange(1, 100000);
    fee_rate->setValue(1);
    fee_rate->setSuffix(tr(" sat/vB"));
    fee_rate->setToolTip(
        tr("The resulting main-chain transaction fee is the recurring BMM security bid."));
    form->addRow(tr("Child chain:"), chain);
    form->addRow(tr("Main-chain fee rate:"), fee_rate);
    layout->addLayout(form);
    auto* proofs_text = new QPlainTextEdit{&input_dialog};
    proofs_text->setPlaceholderText(
        tr("One canonical KDPR proof in hexadecimal per line"));
    layout->addWidget(proofs_text, 1);
    auto* buttons = new QDialogButtonBox{
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &input_dialog};
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Build and Review"));
    connect(buttons, &QDialogButtonBox::accepted,
            &input_dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected,
            &input_dialog, &QDialog::reject);
    layout->addWidget(buttons);
    if (input_dialog.exec() != QDialog::Accepted) return;

    UniValue proofs{UniValue::VARR};
    const QRegularExpression proof_hex{
        QStringLiteral("^(?:[0-9A-Fa-f]{2})+$")};
    for (const QString& line :
         proofs_text->toPlainText().split(
             QRegularExpression{QStringLiteral("\\s+")},
             Qt::SkipEmptyParts)) {
        const QString proof{line.trimmed()};
        if (!proof_hex.match(proof).hasMatch()) {
            QMessageBox::warning(
                this,
                tr("Invalid Deposit Proof"),
                tr("Every KDPR proof must contain complete hexadecimal bytes."));
            return;
        }
        proofs.push_back(proof.toStdString());
    }
    if (proofs.empty()) {
        QMessageBox::warning(
            this,
            tr("Missing Deposit Proof"),
            tr("Provide at least one mature KDPR deposit proof."));
        return;
    }

    UniValue block_params{UniValue::VARR};
    block_params.push_back(chain_id.toStdString());
    block_params.push_back(std::move(proofs));
    UniValue child_block;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        child_block = m_node.executeRpc(
            "createchildimportblock", block_params, "");
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Build child import block"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Build child import block"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const QString block_hash{StringField(child_block, "blockhash")};
    const QString block_hex{StringField(child_block, "block")};
    const QString anchor_script{StringField(child_block, "bmm_anchor_script")};
    const UniValue& deposits{child_block.find_value("deposits")};
    if (StringField(child_block, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0 ||
        !QRegularExpression{QStringLiteral("^[0-9A-Fa-f]{64}$")}
             .match(block_hash).hasMatch() ||
        !proof_hex.match(block_hex).hasMatch() ||
        !proof_hex.match(anchor_script).hasMatch() ||
        !deposits.isArray() || deposits.empty() ||
        !BoolField(child_block, "requires_bmm_anchor") ||
        !BoolField(child_block, "proposal_stored") ||
        !BoolField(child_block, "contextually_valid")) {
        showRpcError(
            tr("Build child import block"),
            tr("The node returned an invalid child block proposal."));
        return;
    }

    UniValue options{UniValue::VOBJ};
    options.pushKV("fee_rate", fee_rate->value());
    UniValue anchor_params{UniValue::VARR};
    anchor_params.push_back(chain_id.toStdString());
    anchor_params.push_back(block_hash.toStdString());
    anchor_params.push_back(std::move(options));
    UniValue anchor;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        anchor = m_node.executeRpc(
            "walletcreatechildanchorpsbt", anchor_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create BMM security bid"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create BMM security bid"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& psbt{anchor.find_value("psbt")};
    const UniValue& security_bid{anchor.find_value("security_bid")};
    if (!psbt.isStr() || !security_bid.isNum() ||
        StringField(anchor, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0 ||
        StringField(anchor, "child_block_hash").compare(
            block_hash, Qt::CaseInsensitive) != 0 ||
        StringField(anchor, "anchor_script").compare(
            anchor_script, Qt::CaseInsensitive) != 0) {
        showRpcError(
            tr("Create BMM security bid"),
            tr("The wallet returned an invalid or mismatched BMM proposal."));
        return;
    }

    QMessageBox confirmation{
        QMessageBox::Warning,
        tr("Confirm BMM Security Bid"),
        tr("Broadcast a main-chain transaction anchoring child block %1?\n\nImported deposits: %2\nChild block size: %3 bytes\nSecurity bid (main-chain fee): %4 KNE\n\nThe validated proposal is already stored durably by this node and will remain available after restart.")
            .arg(block_hash,
                 QString::number(deposits.size()),
                 NumberField(child_block, "size"),
                 QString::fromStdString(security_bid.getValStr())),
        QMessageBox::Yes | QMessageBox::Cancel,
        this};
    confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) return;
    if (!wallet_model || m_wallet_model != wallet_model) {
        showRpcError(
            tr("Submit BMM security bid"),
            tr("The selected wallet changed while preparing the proposal."));
        return;
    }
    WalletModel::UnlockContext unlock_context{wallet_model->requestUnlock()};
    if (!unlock_context.isValid()) return;

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(psbt.get_str());
    submit_params.push_back(chain_id.toStdString());
    submit_params.push_back(block_hash.toStdString());
    submit_params.push_back(security_bid);
    UniValue submitted;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        submitted = m_node.executeRpc(
            "walletsubmitchildanchorpsbt", submit_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Submit BMM security bid"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Submit BMM security bid"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const QString anchor_txid{StringField(submitted, "txid")};
    if (!QRegularExpression{QStringLiteral("^[0-9A-Fa-f]{64}$")}
             .match(anchor_txid).hasMatch() ||
        StringField(submitted, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0 ||
        StringField(submitted, "child_block_hash").compare(
            block_hash, Qt::CaseInsensitive) != 0 ||
        !submitted.find_value("security_bid").isNum() ||
        submitted.find_value("security_bid").getValStr() !=
            security_bid.getValStr()) {
        showRpcError(
            tr("Submit BMM security bid"),
            tr("The wallet returned an invalid BMM submission result."));
        return;
    }

    UniValue proposal{UniValue::VOBJ};
    proposal.pushKV("version", 1);
    proposal.pushKV("chain_id", chain_id.toStdString());
    proposal.pushKV("blockhash", block_hash.toStdString());
    proposal.pushKV("block", block_hex.toStdString());
    proposal.pushKV("anchor_txid", anchor_txid.toStdString());
    proposal.pushKV("security_bid", security_bid);
    const QString proposal_json{QString::fromStdString(proposal.write(2))};

    QDialog result_dialog{this};
    result_dialog.setWindowTitle(tr("Child Proposal Broadcast"));
    result_dialog.setMinimumSize(900, 560);
    auto* result_layout = new QVBoxLayout{&result_dialog};
    auto* result_summary = new QLabel{
        tr("The BMM security bid was broadcast as %1. The child proposal is stored by this node; exporting the JSON below is optional. After confirmation, choose BMM… → Activate a stored confirmed proposal and enter the containing main-chain block hash.")
            .arg(anchor_txid),
        &result_dialog};
    result_summary->setWordWrap(true);
    result_layout->addWidget(result_summary);
    auto* result_text = new QPlainTextEdit{proposal_json, &result_dialog};
    result_text->setReadOnly(true);
    result_text->setLineWrapMode(QPlainTextEdit::NoWrap);
    result_layout->addWidget(result_text, 1);
    auto* result_buttons = new QDialogButtonBox{&result_dialog};
    auto* copy_button = result_buttons->addButton(
        tr("Copy Proposal"), QDialogButtonBox::ActionRole);
    auto* save_button = result_buttons->addButton(
        tr("Save Proposal…"), QDialogButtonBox::ActionRole);
    result_buttons->addButton(QDialogButtonBox::Close);
    result_layout->addWidget(result_buttons);
    connect(copy_button, &QPushButton::clicked, &result_dialog,
            [proposal_json] { GUIUtil::setClipboard(proposal_json); });
    connect(save_button, &QPushButton::clicked, &result_dialog,
            [&, proposal_json, block_hash] {
        const QString filename{GUIUtil::getSaveFileName(
            &result_dialog,
            tr("Save Child Proposal"),
            block_hash + QStringLiteral(".kproposal"),
            tr("Kronein Child Proposal") +
                QStringLiteral(" (*.kproposal)"),
            nullptr)};
        if (filename.isEmpty()) return;
        QSaveFile file{filename};
        const QByteArray bytes{proposal_json.toUtf8()};
        if (!file.open(QIODevice::WriteOnly) ||
            file.write(bytes) != bytes.size() || !file.commit()) {
            QMessageBox::critical(
                &result_dialog,
                tr("Save Proposal Failed"),
                tr("Could not save the proposal to %1: %2")
                    .arg(filename, file.errorString()));
            return;
        }
        QMessageBox::information(
            &result_dialog,
            tr("Proposal Saved"),
            tr("The child proposal was saved to %1.").arg(filename));
    });
    connect(result_buttons, &QDialogButtonBox::rejected,
            &result_dialog, &QDialog::reject);
    result_dialog.exec();
    refresh();
}

void ChildChainDialog::submitRegistryOperation(const char* operation,
                                               const QString& chain_id,
                                               UniValue parameters,
                                               const QString& result_details)
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
    const UniValue& proposed_burn{created.find_value("registration_burn")};
    if (!created_operation.isStr() ||
        QString::fromStdString(created_operation.get_str()) != operation_name ||
        !created_chain.isStr() ||
        QString::fromStdString(created_chain.get_str()) != chain_id ||
        !psbt.isStr() || !fee.isNum() || !proposed_burn.isNum()) {
        showRpcError(tr("Create registry operation"),
                     tr("The wallet returned an invalid registry proposal."));
        return;
    }

    const bool registering{operation_name == QStringLiteral("register")};
    const bool retiring{operation_name == QStringLiteral("retire")};
    QMessageBox confirmation{
        QMessageBox::Warning,
        registering ? tr("Confirm Child Registration")
                    : retiring ? tr("Confirm Permanent Retirement")
                               : tr("Confirm Metadata Update"),
        registering
            ? tr("Register child chain %1?\n\nRegistration permanently burns %2 KNE.\nMain-chain fee: %3 KNE\n\nThe burn is not refundable, even if the child chain is never operated.")
                  .arg(chain_id,
                       QString::fromStdString(proposed_burn.getValStr()),
                       QString::fromStdString(fee.getValStr()))
            : retiring
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
    if (registering) submit_params.push_back(proposed_burn);
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
        registration_burn.getValStr() != proposed_burn.getValStr()) {
        showRpcError(tr("Submit registry operation"),
                     tr("The wallet returned an invalid registry result."));
        return;
    }

    QMessageBox result{
        QMessageBox::Information,
        registering ? tr("Registration Submitted")
                    : retiring ? tr("Retirement Submitted")
                               : tr("Update Submitted"),
        tr("The registry operation was broadcast.\n\nTransaction: %1\nChild chain: %2")
            .arg(QString::fromStdString(txid.get_str()), chain_id),
        QMessageBox::Ok,
        this};
    if (!result_details.isEmpty()) result.setDetailedText(result_details);
    result.exec();
    refresh();
}

void ChildChainDialog::registerChildChain()
{
    if (!m_wallet_model) return;
    const QPointer<WalletModel> wallet_model{m_wallet_model};
    const std::string wallet_uri{walletUri()};

    UniValue list_params{UniValue::VARR};
    list_params.push_back(1);
    UniValue unspent;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        unspent = m_node.executeRpc("listunspent", list_params, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List registration anchors"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List registration anchors"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();
    if (!unspent.isArray()) {
        showRpcError(tr("List registration anchors"),
                     tr("The wallet returned an invalid unspent-output list."));
        return;
    }

    QDialog input_dialog{this};
    input_dialog.setWindowTitle(tr("Register Reference Child Chain"));
    auto* layout = new QVBoxLayout{&input_dialog};
    auto* warning = new QLabel{
        tr("Registration consumes the selected confirmed wallet output and permanently burns the protocol registration amount."),
        &input_dialog};
    warning->setWordWrap(true);
    layout->addWidget(warning);

    auto* form = new QFormLayout;
    auto* anchor = new QComboBox{&input_dialog};
    for (const UniValue& output : unspent.getValues()) {
        if (!output.isObject()) continue;
        const QString txid{StringField(output, "txid")};
        if (txid.isEmpty() ||
            !output.find_value("vout").isNum() ||
            !output.find_value("amount").isNum() ||
            !BoolField(output, "spendable") || !BoolField(output, "safe")) {
            continue;
        }
        const int vout{output.find_value("vout").getInt<int>()};
        const QString amount{QString::fromStdString(
            output.find_value("amount").getValStr())};
        anchor->addItem(
            tr("%1:%2 — %3 KNE").arg(txid, QString::number(vout), amount),
            txid);
        anchor->setItemData(anchor->count() - 1, vout, Qt::UserRole + 1);
    }
    if (anchor->count() == 0) {
        QMessageBox::warning(
            this,
            tr("No Registration Anchor"),
            tr("The selected wallet has no safe, spendable output with at least one confirmation."));
        return;
    }

    auto* metadata_hash = new QLineEdit{&input_dialog};
    metadata_hash->setValidator(new QRegularExpressionValidator{
        QRegularExpression{QStringLiteral("[0-9A-Fa-f]{64}")}, metadata_hash});
    metadata_hash->setPlaceholderText(tr("32-byte external metadata commitment in hexadecimal"));
    auto* max_block_weight = new QSpinBox{&input_dialog};
    max_block_weight->setRange(
        chainregistry::MIN_CHILD_BLOCK_WEIGHT,
        chainregistry::MAX_CHILD_BLOCK_WEIGHT);
    max_block_weight->setSingleStep(chainregistry::CHILD_BLOCK_WEIGHT_GRANULARITY);
    max_block_weight->setValue(chainregistry::MAX_CHILD_BLOCK_WEIGHT);
    auto* deposit_maturity = new QSpinBox{&input_dialog};
    deposit_maturity->setRange(
        chainregistry::MIN_DEPOSIT_MATURITY,
        chainregistry::MAX_DEPOSIT_MATURITY);
    deposit_maturity->setValue(chainregistry::DEFAULT_DEPOSIT_MATURITY);
    form->addRow(tr("Registration anchor:"), anchor);
    form->addRow(tr("Metadata hash:"), metadata_hash);
    form->addRow(tr("Maximum block weight:"), max_block_weight);
    form->addRow(tr("Deposit maturity:"), deposit_maturity);
    layout->addLayout(form);

    auto* buttons = new QDialogButtonBox{
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &input_dialog};
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Review Registration"));
    connect(buttons, &QDialogButtonBox::accepted, &input_dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &input_dialog, &QDialog::reject);
    layout->addWidget(buttons);
    if (input_dialog.exec() != QDialog::Accepted) return;
    const QString metadata_commitment{metadata_hash->text().trimmed()};
    if (!metadata_hash->hasAcceptableInput() ||
        metadata_commitment == QString(64, QLatin1Char{'0'})) {
        QMessageBox::warning(
            this,
            tr("Invalid Metadata Hash"),
            tr("Enter exactly 32 non-zero bytes (64 hexadecimal characters)."));
        return;
    }
    if (!wallet_model) {
        showRpcError(tr("Create child registration"),
                     tr("The selected wallet is no longer available."));
        return;
    }

    UniValue registration_anchor{UniValue::VOBJ};
    registration_anchor.pushKV(
        "txid", anchor->currentData(Qt::UserRole).toString().toStdString());
    registration_anchor.pushKV(
        "vout", anchor->currentData(Qt::UserRole + 1).toInt());
    UniValue manifest_params{UniValue::VARR};
    manifest_params.push_back(registration_anchor);
    manifest_params.push_back(metadata_commitment.toStdString());
    manifest_params.push_back(max_block_weight->value());
    manifest_params.push_back(deposit_maturity->value());

    UniValue definition;
    UniValue control_address;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        definition = m_node.executeRpc(
            "createreferencechildmanifest", manifest_params, "");
        control_address = m_node.executeRpc(
            "getnewaddress", UniValue{UniValue::VARR}, wallet_uri);
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create child registration"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Create child registration"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& chain_value{definition.find_value("chain_id")};
    const UniValue& genesis_hash{definition.find_value("genesis_hash")};
    const UniValue& manifest{definition.find_value("manifest")};
    if (!chain_value.isStr() || !genesis_hash.isStr() ||
        !manifest.isObject() || !control_address.isStr()) {
        showRpcError(tr("Create child registration"),
                     tr("The node returned an invalid reference-child definition."));
        return;
    }
    const UniValue& spec{manifest.find_value("spec")};
    if (!spec.isObject()) {
        showRpcError(tr("Create child registration"),
                     tr("The node returned an invalid reference-child definition."));
        return;
    }

    UniValue wallet_spec{UniValue::VOBJ};
    for (const char* key : {"template_id", "template_version",
                            "consensus_parameters", "anchoring_policy"}) {
        const UniValue& value{spec.find_value(key)};
        if (value.isNull()) {
            showRpcError(tr("Create child registration"),
                         tr("The node returned an incomplete reference-child specification."));
            return;
        }
        wallet_spec.pushKV(key, value);
    }

    UniValue parameters{UniValue::VOBJ};
    parameters.pushKV("registration_anchor", registration_anchor);
    parameters.pushKV("spec", std::move(wallet_spec));
    parameters.pushKV("child_genesis_hash", genesis_hash);
    parameters.pushKV("metadata_hash", metadata_commitment.toStdString());
    parameters.pushKV("control_address", control_address);

    UniValue local_definition{UniValue::VOBJ};
    local_definition.pushKV("registration_anchor", std::move(registration_anchor));
    local_definition.pushKV("manifest", manifest);
    const QString details{
        tr("Save this canonical manifest. After the registration confirms, use Add Manifest… to configure the child locally.\n\n%1")
            .arg(QString::fromStdString(local_definition.write(2)))};
    if (m_wallet_model != wallet_model) {
        showRpcError(tr("Create child registration"),
                     tr("The selected wallet changed while preparing the registration."));
        return;
    }
    submitRegistryOperation(
        "register",
        QString::fromStdString(chain_value.get_str()),
        std::move(parameters),
        details);
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

void ChildChainDialog::showBalance()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty() || !m_wallet_model) return;

    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    UniValue result;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        result = m_node.executeRpc("getbalances", params, walletUri());
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Read child balance"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("Read child balance"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& mine{result.find_value("mine")};
    const UniValue& trusted{mine.find_value("trusted")};
    const UniValue& pending{mine.find_value("untrusted_pending")};
    const UniValue& immature{mine.find_value("immature")};
    const UniValue& last_processed{result.find_value("lastprocessedblock")};
    const QString tip_hash{StringField(last_processed, "hash")};
    if (!result.isObject() ||
        StringField(result, "chain_id").compare(
            chain_id, Qt::CaseInsensitive) != 0 ||
        !mine.isObject() || !trusted.isNum() || !pending.isNum() ||
        !immature.isNum() || !last_processed.isObject() ||
        !last_processed.find_value("height").isNum() ||
        !QRegularExpression{QStringLiteral("^[0-9A-Fa-f]{64}$")}
             .match(tip_hash)
             .hasMatch()) {
        showRpcError(tr("Read child balance"),
                     tr("The wallet returned an invalid child-balance snapshot."));
        return;
    }

    QMessageBox::information(
        this,
        tr("Child Wallet Balance"),
        tr("Child chain: %1\n\n"
           "Confirmed spendable: %2\n"
           "Unconfirmed: %3\n"
           "Immature: %4\n\n"
           "Processed child tip: height %5\n%6\n\n"
           "These amounts belong only to this child ledger and are not included in the main-chain wallet balance.")
            .arg(chain_id,
                 QString::fromStdString(trusted.getValStr()),
                 QString::fromStdString(pending.getValStr()),
                 QString::fromStdString(immature.getValStr()),
                 NumberField(last_processed, "height"),
                 tip_hash));
}

void ChildChainDialog::showActivity()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty() || !m_wallet_model) return;

    UniValue params{UniValue::VARR};
    params.push_back("*");
    params.push_back(100);
    params.push_back(0);
    params.push_back(chain_id.toStdString());
    UniValue result;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        result = m_node.executeRpc("listtransactions", params, walletUri());
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List child activity"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List child activity"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    if (!result.isArray()) {
        showRpcError(tr("List child activity"),
                     tr("The wallet returned an invalid child-activity list."));
        return;
    }

    QDialog dialog{this};
    dialog.setWindowTitle(tr("Child Activity — %1").arg(chain_id));
    dialog.setMinimumSize(1150, 430);
    auto* layout = new QVBoxLayout{&dialog};
    auto* summary = new QLabel{
        tr("Showing the %n most recent child wallet activity entry or entries.",
           nullptr, static_cast<int>(result.size())),
        &dialog};
    summary->setWordWrap(true);
    layout->addWidget(summary);

    auto* table = new QTableWidget{&dialog};
    table->setObjectName(QStringLiteral("childActivityTable"));
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels({
        tr("Time"),
        tr("Category"),
        tr("Amount"),
        tr("Confirmations"),
        tr("Label"),
        tr("Child recipient"),
        tr("Transaction ID"),
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);

    const QRegularExpression hex_256{QStringLiteral("^[0-9A-Fa-f]{64}$")};
    const auto& entries{result.getValues()};
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        const UniValue& entry{*it};
        const QString entry_chain{StringField(entry, "chain_id")};
        const QString category{StringField(entry, "category")};
        const QString category_label{TransactionCategoryLabel(category)};
        const QString txid{StringField(entry, "txid")};
        const QString recipient{StringField(entry, "recipient")};
        const UniValue& amount{entry.find_value("amount")};
        const UniValue& confirmations{entry.find_value("confirmations")};
        const UniValue& time{entry.find_value("time")};
        const UniValue& label{entry.find_value("label")};
        if (!entry.isObject() ||
            entry_chain.compare(chain_id, Qt::CaseInsensitive) != 0 ||
            category_label.isEmpty() || !amount.isNum() ||
            !confirmations.isNum() || !time.isNum() ||
            !hex_256.match(txid).hasMatch() ||
            (!recipient.isEmpty() && !hex_256.match(recipient).hasMatch()) ||
            (!label.isNull() && !label.isStr())) {
            showRpcError(tr("List child activity"),
                         tr("The wallet returned a malformed child-activity entry."));
            return;
        }

        const int row{table->rowCount()};
        table->insertRow(row);
        table->setItem(row, 0, new QTableWidgetItem{
            GUIUtil::dateTimeStr(time.getInt<int64_t>())});
        table->setItem(row, 1, new QTableWidgetItem{category_label});
        table->setItem(row, 2, new QTableWidgetItem{
            QString::fromStdString(amount.getValStr()) + QStringLiteral(" KNE")});
        table->setItem(row, 3, new QTableWidgetItem{
            QString::fromStdString(confirmations.getValStr())});
        table->setItem(row, 4, new QTableWidgetItem{
            label.isStr() ? QString::fromStdString(label.get_str()) : QString{}});
        table->setItem(row, 5, new QTableWidgetItem{recipient});
        table->setItem(row, 6, new QTableWidgetItem{txid});
    }
    layout->addWidget(table, 1);

    auto* buttons = new QDialogButtonBox{QDialogButtonBox::Close, &dialog};
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    dialog.exec();
}

void ChildChainDialog::showDeposits()
{
    const QString chain_id{selectedChainId()};
    if (chain_id.isEmpty() || !m_wallet_model) return;

    UniValue params{UniValue::VARR};
    params.push_back(chain_id.toStdString());
    params.push_back(100);
    params.push_back(0);
    UniValue result;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        result = m_node.executeRpc(
            "listwalletchaindeposits", params, walletUri());
    } catch (UniValue& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List child deposits"), RpcErrorMessage(error));
        return;
    } catch (const std::exception& error) {
        QApplication::restoreOverrideCursor();
        showRpcError(tr("List child deposits"),
                     QString::fromStdString(error.what()));
        return;
    }
    QApplication::restoreOverrideCursor();

    const UniValue& deposits{result.find_value("deposits")};
    if (!result.isObject() || !deposits.isArray() ||
        !result.find_value("total").isNum() ||
        !result.find_value("returned").isNum()) {
        showRpcError(tr("List child deposits"),
                     tr("The wallet returned an invalid child-deposit list."));
        return;
    }

    QDialog dialog{this};
    dialog.setWindowTitle(tr("Child Deposits — %1").arg(chain_id));
    dialog.setMinimumSize(1100, 430);
    auto* layout = new QVBoxLayout{&dialog};
    const int total{result.find_value("total").getInt<int>()};
    auto* summary = new QLabel{
        tr("Showing %1 of %n irreversible deposit(s) created by the selected wallet.",
           nullptr, total)
            .arg(NumberField(result, "returned")),
        &dialog};
    summary->setWordWrap(true);
    layout->addWidget(summary);

    auto* table = new QTableWidget{&dialog};
    table->setObjectName(QStringLiteral("childDepositTable"));
    table->setColumnCount(6);
    table->setHorizontalHeaderLabels({
        tr("Status"),
        tr("Amount"),
        tr("Confirmations"),
        tr("Main-chain outpoint"),
        tr("Deposit ID"),
        tr("Child recipient"),
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);

    constexpr int TXID_ROLE{Qt::UserRole};
    constexpr int VOUT_ROLE{Qt::UserRole + 1};
    constexpr int DEPOSIT_ID_ROLE{Qt::UserRole + 2};
    constexpr int PROOF_ELIGIBLE_ROLE{Qt::UserRole + 3};
    for (const UniValue& deposit : deposits.getValues()) {
        if (!deposit.isObject()) continue;
        const QString txid{StringField(deposit, "txid")};
        const QString deposit_id{StringField(deposit, "deposit_id")};
        const QString deposit_chain{StringField(deposit, "chain_id")};
        const UniValue& vout_value{deposit.find_value("vout")};
        const UniValue& recipient_type{deposit.find_value("recipient_type")};
        if (txid.isEmpty() || deposit_id.isEmpty() ||
            deposit_chain.compare(chain_id, Qt::CaseInsensitive) != 0 ||
            !vout_value.isNum() || !recipient_type.isNum()) {
            showRpcError(tr("List child deposits"),
                         tr("The wallet returned a malformed child-deposit entry."));
            return;
        }

        const QString status{StringField(deposit, "status")};
        const int row{table->rowCount()};
        table->insertRow(row);
        auto* status_item = new QTableWidgetItem{DepositStatusLabel(status)};
        status_item->setData(TXID_ROLE, txid);
        status_item->setData(VOUT_ROLE, vout_value.getInt<int>());
        status_item->setData(DEPOSIT_ID_ROLE, deposit_id);
        status_item->setData(
            PROOF_ELIGIBLE_ROLE, status == QStringLiteral("confirmed"));
        table->setItem(row, 0, status_item);
        table->setItem(row, 1, new QTableWidgetItem{NumberField(deposit, "amount") + QStringLiteral(" KNE")});
        table->setItem(row, 2, new QTableWidgetItem{NumberField(deposit, "confirmations")});
        table->setItem(row, 3, new QTableWidgetItem{QStringLiteral("%1:%2").arg(txid, NumberField(deposit, "vout"))});
        table->setItem(row, 4, new QTableWidgetItem{deposit_id});
        table->setItem(row, 5, new QTableWidgetItem{
            QStringLiteral("%1:%2")
                .arg(NumberField(deposit, "recipient_type"),
                     StringField(deposit, "recipient"))});
    }
    layout->addWidget(table, 1);

    auto* buttons = new QDialogButtonBox{&dialog};
    auto* export_button = buttons->addButton(
        tr("Inspect / Export Proof…"), QDialogButtonBox::ActionRole);
    export_button->setObjectName(QStringLiteral("childDepositExportProofButton"));
    buttons->addButton(QDialogButtonBox::Close);
    layout->addWidget(buttons);

    const auto update_export_button = [table, export_button] {
        const QTableWidgetItem* item{table->item(table->currentRow(), 0)};
        export_button->setEnabled(
            item && item->data(PROOF_ELIGIBLE_ROLE).toBool());
    };
    connect(table, &QTableWidget::itemSelectionChanged,
            &dialog, update_export_button);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(export_button, &QPushButton::clicked, &dialog, [&, table] {
        const QTableWidgetItem* item{table->item(table->currentRow(), 0)};
        if (!item) return;
        const QString txid{item->data(TXID_ROLE).toString()};
        const int vout{item->data(VOUT_ROLE).toInt()};
        const QString expected_deposit_id{item->data(DEPOSIT_ID_ROLE).toString()};

        UniValue proof_params{UniValue::VARR};
        proof_params.push_back(txid.toStdString());
        proof_params.push_back(vout);
        UniValue status_result;
        QApplication::setOverrideCursor(Qt::WaitCursor);
        try {
            status_result = m_node.executeRpc(
                "getdepositstatus", proof_params, "");
        } catch (UniValue& error) {
            QApplication::restoreOverrideCursor();
            showRpcError(tr("Inspect deposit proof"), RpcErrorMessage(error));
            return;
        } catch (const std::exception& error) {
            QApplication::restoreOverrideCursor();
            showRpcError(tr("Inspect deposit proof"),
                         QString::fromStdString(error.what()));
            return;
        }
        QApplication::restoreOverrideCursor();

        const UniValue& indexed_deposit{status_result.find_value("deposit")};
        const UniValue& destination{indexed_deposit.find_value("destination")};
        if (!status_result.isObject() || !BoolField(status_result, "found") ||
            !indexed_deposit.isObject() || !destination.isObject() ||
            StringField(status_result, "deposit_id").compare(
                expected_deposit_id, Qt::CaseInsensitive) != 0 ||
            StringField(indexed_deposit, "deposit_id").compare(
                expected_deposit_id, Qt::CaseInsensitive) != 0 ||
            StringField(destination, "chain_id").compare(
                chain_id, Qt::CaseInsensitive) != 0) {
            showRpcError(tr("Inspect deposit proof"),
                         tr("The active main-chain deposit index does not match the selected wallet deposit."));
            return;
        }
        if (!BoolField(indexed_deposit, "proof_available")) {
            QMessageBox::warning(
                &dialog,
                tr("Deposit Proof Unavailable"),
                tr("The deposit is indexed, but its containing block data is unavailable. It may have been pruned; export the proof from a node that still stores that block."));
            return;
        }

        UniValue proof_result;
        QApplication::setOverrideCursor(Qt::WaitCursor);
        try {
            proof_result = m_node.executeRpc(
                "getdepositproof", proof_params, "");
        } catch (UniValue& error) {
            QApplication::restoreOverrideCursor();
            showRpcError(tr("Export deposit proof"), RpcErrorMessage(error));
            return;
        } catch (const std::exception& error) {
            QApplication::restoreOverrideCursor();
            showRpcError(tr("Export deposit proof"),
                         QString::fromStdString(error.what()));
            return;
        }
        QApplication::restoreOverrideCursor();

        const QString proof_hex{StringField(proof_result, "proof")};
        const UniValue& proof_deposit{proof_result.find_value("deposit")};
        const UniValue& proof_destination{proof_deposit.find_value("destination")};
        if (!proof_result.isObject() || proof_hex.isEmpty() ||
            !QRegularExpression{QStringLiteral("^(?:[0-9A-Fa-f]{2})+$")}
                 .match(proof_hex).hasMatch() ||
            !proof_deposit.isObject() || !proof_destination.isObject() ||
            !proof_result.find_value("proof_version").isNum() ||
            !proof_deposit.find_value("confirmations").isNum() ||
            StringField(proof_deposit, "deposit_id").compare(
                expected_deposit_id, Qt::CaseInsensitive) != 0 ||
            StringField(proof_destination, "chain_id").compare(
                chain_id, Qt::CaseInsensitive) != 0) {
            showRpcError(tr("Export deposit proof"),
                         tr("The node returned an invalid or mismatched KDPR proof."));
            return;
        }
        const QByteArray proof_bytes{QByteArray::fromHex(proof_hex.toLatin1())};

        QDialog proof_dialog{&dialog};
        proof_dialog.setWindowTitle(tr("KDPR Deposit Proof — %1").arg(expected_deposit_id));
        proof_dialog.setMinimumSize(900, 560);
        auto* proof_layout = new QVBoxLayout{&proof_dialog};
        const int confirmations{
            proof_deposit.find_value("confirmations").getInt<int>()};
        auto* proof_summary = new QLabel{
            tr("Canonical KDPR v%1 proof for %2:%3 (%n confirmation(s)).",
               nullptr, confirmations)
                .arg(NumberField(proof_result, "proof_version"),
                     txid,
                     QString::number(vout)),
            &proof_dialog};
        proof_summary->setWordWrap(true);
        proof_layout->addWidget(proof_summary);
        auto* proof_text = new QPlainTextEdit{
            QString::fromStdString(proof_result.write(2)), &proof_dialog};
        proof_text->setReadOnly(true);
        proof_text->setLineWrapMode(QPlainTextEdit::NoWrap);
        proof_layout->addWidget(proof_text, 1);
        auto* proof_buttons = new QDialogButtonBox{&proof_dialog};
        auto* copy_button = proof_buttons->addButton(
            tr("Copy Proof Hex"), QDialogButtonBox::ActionRole);
        auto* save_button = proof_buttons->addButton(
            tr("Save Binary Proof…"), QDialogButtonBox::ActionRole);
        proof_buttons->addButton(QDialogButtonBox::Close);
        proof_layout->addWidget(proof_buttons);
        connect(copy_button, &QPushButton::clicked, &proof_dialog,
                [proof_hex] { GUIUtil::setClipboard(proof_hex); });
        connect(save_button, &QPushButton::clicked, &proof_dialog,
                [&, proof_bytes, expected_deposit_id] {
            const QString filename{GUIUtil::getSaveFileName(
                &proof_dialog,
                tr("Save KDPR Deposit Proof"),
                expected_deposit_id + QStringLiteral(".kdpr"),
                tr("Kronein Deposit Proof (Binary)") +
                    QStringLiteral(" (*.kdpr)"),
                nullptr)};
            if (filename.isEmpty()) return;
            QSaveFile file{filename};
            if (!file.open(QIODevice::WriteOnly) ||
                file.write(proof_bytes) != proof_bytes.size() ||
                !file.commit()) {
                QMessageBox::critical(
                    &proof_dialog,
                    tr("Save Proof Failed"),
                    tr("Could not save the KDPR proof to %1: %2")
                        .arg(filename, file.errorString()));
                return;
            }
            QMessageBox::information(
                &proof_dialog,
                tr("Proof Saved"),
                tr("The canonical binary KDPR proof was saved to %1.")
                    .arg(filename));
        });
        connect(proof_buttons, &QDialogButtonBox::rejected,
                &proof_dialog, &QDialog::reject);
        proof_dialog.exec();
    });

    if (table->rowCount() > 0) table->selectRow(0);
    update_export_button();
    dialog.exec();
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
    recipient->setToolTip(
        tr("This is a child-chain receiving key, not a main-chain address."));
    auto* recipient_row = new QWidget{&input_dialog};
    auto* recipient_layout = new QHBoxLayout{recipient_row};
    recipient_layout->setContentsMargins(0, 0, 0, 0);
    recipient_layout->addWidget(recipient, 1);
    auto* new_recipient = new QPushButton{tr("New Wallet Recipient"), recipient_row};
    new_recipient->setObjectName(QStringLiteral("childChainNewRecipientButton"));
    new_recipient->setToolTip(
        tr("Derive and save a receiving key owned by the selected wallet and bound to this exact child chain."));
    recipient_layout->addWidget(new_recipient);
    connect(new_recipient, &QPushButton::clicked, &input_dialog,
            [this, chain_id, wallet_uri, recipient, recipient_type] {
        UniValue params{UniValue::VARR};
        params.push_back(chain_id.toStdString());
        params.push_back("");
        QApplication::setOverrideCursor(Qt::WaitCursor);
        UniValue result;
        try {
            result = m_node.executeRpc(
                "getnewchildrecipient", params, wallet_uri);
        } catch (UniValue& error) {
            QApplication::restoreOverrideCursor();
            showRpcError(tr("Create child recipient"), RpcErrorMessage(error));
            return;
        } catch (const std::exception& error) {
            QApplication::restoreOverrideCursor();
            showRpcError(tr("Create child recipient"),
                         QString::fromStdString(error.what()));
            return;
        }
        QApplication::restoreOverrideCursor();

        const QString returned_chain{StringField(result, "chain_id")};
        const QString returned_recipient{StringField(result, "recipient")};
        const UniValue& returned_type{result.find_value("recipient_type")};
        if (returned_chain.compare(chain_id, Qt::CaseInsensitive) != 0 ||
            !returned_type.isNum() || returned_type.getInt<int>() != 1 ||
            !QRegularExpression{QStringLiteral("^[0-9A-Fa-f]{64}$")}
                 .match(returned_recipient).hasMatch()) {
            showRpcError(
                tr("Create child recipient"),
                tr("The wallet returned an invalid child recipient."));
            return;
        }
        recipient_type->setValue(1);
        recipient->setText(returned_recipient);
    });
    auto* amount = new BitcoinAmountField{&input_dialog};
    amount->SetAllowEmpty(false);
    amount->SetMinValue(1);
    amount->SetMaxValue(MAX_MONEY);
    form->addRow(tr("Child chain:"), chain);
    form->addRow(tr("Recipient type:"), recipient_type);
    form->addRow(tr("Recipient bytes:"), recipient_row);
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
