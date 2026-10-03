// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/dealerauthoritydialog.h>

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <interfaces/node.h>
#include <random.h>
#ifdef ENABLE_WALLET
#include <qt/walletmodel.h>
#endif

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSpinBox>
#include <QUrl>
#include <QVBoxLayout>

#include <stdexcept>

namespace {
QString Json(const UniValue& value) { return QString::fromStdString(value.write(2)); }

UniValue Signatures(const QPlainTextEdit* input)
{
    const auto text{input->toPlainText().trimmed()};
    if (text.isEmpty()) return UniValue{UniValue::VARR};
    UniValue result;
    if (text.size() > 4096 || !result.read(text.toStdString()) || !result.isArray()) {
        throw std::runtime_error{DealerAuthorityDialog::tr("Signatures must be a JSON array of at most five key_index/signature entries").toStdString()};
    }
    return result;
}
} // namespace

DealerAuthorityDialog::DealerAuthorityDialog(interfaces::Node& node, QWidget* parent)
    : QDialog{parent}, m_node{node}
{
    setObjectName(QStringLiteral("dealerAuthorityDialog"));
    setWindowTitle(tr("Dealer Authority"));
    resize(900, 800);
    auto* layout{new QVBoxLayout{this}};
    auto* guidance{new QLabel{tr("Coordinate authority operations on the main chain. Export the proposal for independent offline verification and signing; paste only public signatures here. Never enter authority private keys. A rotation requires both quorums and activates 144 blocks after inclusion."), this}};
    guidance->setWordWrap(true);
    layout->addWidget(guidance);
    m_status = new QPlainTextEdit{this};
    m_status->setObjectName(QStringLiteral("dealerAuthorityStatus"));
    m_status->setReadOnly(true);
    m_status->setMaximumHeight(160);
    layout->addWidget(m_status);
    auto* form{new QFormLayout};
    m_operation = new QComboBox{this};
    m_operation->setObjectName(QStringLiteral("dealerAuthorityOperation"));
    m_operation->addItem(tr("Authorize dealer"), QStringLiteral("authorize_dealer"));
    m_operation->addItem(tr("Update dealer quota or payout"), QStringLiteral("update_dealer"));
    m_operation->addItem(tr("Revoke dealer"), QStringLiteral("revoke_dealer"));
    m_operation->addItem(tr("Rotate authority"), QStringLiteral("rotate_authority"));
    form->addRow(tr("Operation:"), m_operation);
    m_dealer = new QLineEdit{this};
    m_dealer->setMaxLength(64);
    form->addRow(tr("Dealer ID (update/revoke):"), m_dealer);
    m_control = new QLineEdit{this};
    m_control->setObjectName(QStringLiteral("dealerAuthorityControl"));
    m_control->setMaxLength(64);
    form->addRow(tr("Dealer x-only control key (authorize):"), m_control);
    m_payout = new QLineEdit{this};
    m_payout->setObjectName(QStringLiteral("dealerAuthorityPayout"));
    m_payout->setMaxLength(128);
    form->addRow(tr("Dealer payout address (authorize/update):"), m_payout);
    m_licenses = new QSpinBox{this};
    m_licenses->setRange(0, 10);
    m_licenses->setValue(10);
    form->addRow(tr("Licenses (initially 10; add at most 10):"), m_licenses);
    m_next_keys = new QPlainTextEdit{this};
    m_next_keys->setObjectName(QStringLiteral("dealerAuthorityNextKeys"));
    m_next_keys->setMaximumHeight(90);
    form->addRow(tr("New authority keys (sorted, one per line):"), m_next_keys);
    layout->addLayout(form);
    m_signatures = new QPlainTextEdit{this};
    m_signatures->setObjectName(QStringLiteral("dealerAuthoritySignatures"));
    m_signatures->setMaximumHeight(65);
    m_signatures->setPlaceholderText(QStringLiteral("[{\"key_index\":0,\"signature\":\"...\"}, ...]"));
    layout->addWidget(new QLabel{tr("Current quorum signatures:"), this});
    layout->addWidget(m_signatures);
    m_next_signatures = new QPlainTextEdit{this};
    m_next_signatures->setObjectName(QStringLiteral("dealerAuthorityNextSignatures"));
    m_next_signatures->setMaximumHeight(65);
    layout->addWidget(new QLabel{tr("New quorum signatures (rotation only):"), this});
    layout->addWidget(m_next_signatures);
    m_details = new QPlainTextEdit{this};
    m_details->setObjectName(QStringLiteral("dealerAuthorityProposal"));
    m_details->setReadOnly(true);
    layout->addWidget(m_details, 1);
    auto* buttons{new QDialogButtonBox{this}};
    auto* refresh_button{buttons->addButton(tr("Refresh"), QDialogButtonBox::ActionRole)};
    m_prepare = buttons->addButton(tr("Prepare Proposal"), QDialogButtonBox::ActionRole);
    m_prepare->setObjectName(QStringLiteral("dealerAuthorityPrepare"));
    m_verify = buttons->addButton(tr("Verify Signatures"), QDialogButtonBox::ActionRole);
    m_verify->setObjectName(QStringLiteral("dealerAuthorityVerify"));
    m_export = buttons->addButton(tr("Export Proposal…"), QDialogButtonBox::ActionRole);
    m_submit = buttons->addButton(tr("Fund and Submit…"), QDialogButtonBox::ActionRole);
    m_submit->setObjectName(QStringLiteral("dealerAuthoritySubmit"));
    buttons->addButton(QDialogButtonBox::Close);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect(refresh_button, &QPushButton::clicked, this, [this] { guarded([this] { refresh(); }); });
    connect(m_prepare, &QPushButton::clicked, this, [this] { guarded([this] { prepare(); }); });
    connect(m_verify, &QPushButton::clicked, this, [this] { guarded([this] { verify(); }); });
    connect(m_export, &QPushButton::clicked, this, [this] { guarded([this] { exportProposal(); }); });
#ifdef ENABLE_WALLET
    connect(m_submit, &QPushButton::clicked, this, [this] { guarded([this] { submit(); }); });
#endif
    const auto change_operation = [this] {
        invalidate();
        const auto op{operation()};
        m_dealer->setEnabled(op == "update_dealer" || op == "revoke_dealer");
        m_control->setEnabled(op == "authorize_dealer");
        m_payout->setEnabled(op == "authorize_dealer" || op == "update_dealer");
        m_licenses->setEnabled(op == "update_dealer");
        m_next_keys->setEnabled(op == "rotate_authority");
        m_next_signatures->setEnabled(op == "rotate_authority");
    };
    connect(m_operation, &QComboBox::currentIndexChanged, this, change_operation);
    for (auto* input : {m_dealer, m_control, m_payout}) connect(input, &QLineEdit::textChanged, this, [this] { invalidate(); });
    connect(m_licenses, &QSpinBox::valueChanged, this, [this] { invalidate(); });
    connect(m_next_keys, &QPlainTextEdit::textChanged, this, [this] { invalidate(); });
    for (auto* input : {m_signatures, m_next_signatures}) {
        connect(input, &QPlainTextEdit::textChanged, this, [this] { m_submit->setEnabled(false); });
    }
    change_operation();
    guarded([this] { refresh(); });
}

void DealerAuthorityDialog::guarded(const std::function<void()>& action)
{
    try {
        action();
    } catch (const UniValue& error) {
        m_submit->setEnabled(false);
        QMessageBox::warning(this, tr("Dealer Authority"), Json(error));
    } catch (const std::exception& error) {
        m_submit->setEnabled(false);
        QMessageBox::warning(this, tr("Dealer Authority"), QString::fromStdString(error.what()));
    }
}

UniValue DealerAuthorityDialog::call(const char* method, UniValue parameters, const std::string& uri)
{
    return m_node.executeRpc(method, parameters, uri);
}

std::string DealerAuthorityDialog::operation() const { return m_operation->currentData().toString().toStdString(); }

void DealerAuthorityDialog::invalidate()
{
    m_parameters = UniValue{};
    m_proposal = UniValue{};
    m_verify->setEnabled(false);
    m_export->setEnabled(false);
    m_submit->setEnabled(false);
    m_details->clear();
}

void DealerAuthorityDialog::refresh()
{
    invalidate();
    m_info = call("getchainregistryinfo");
    m_status->setPlainText(Json(m_info));
    m_prepare->setEnabled(m_info["active_for_next_block"].get_bool());
}

UniValue DealerAuthorityDialog::build(const UniValue& parameters)
{
    UniValue args{UniValue::VARR};
    args.push_back(operation());
    args.push_back(parameters);
    return call("createchainregistryoperation", std::move(args));
}

void DealerAuthorityDialog::prepare()
{
    refresh();
    if (!m_info["active_for_next_block"].get_bool()) throw std::runtime_error{DealerAuthorityDialog::tr("Registry is not active for the next block").toStdString()};
    UniValue parameters{UniValue::VOBJ};
    const auto sequence{m_info["authority_sequence"].getInt<uint64_t>()};
    if (sequence == UINT64_MAX) throw std::runtime_error{DealerAuthorityDialog::tr("Authority sequence exhausted").toStdString()};
    parameters.pushKV("authority_sequence", sequence + 1);
    const auto op{operation()};
    if (op == "authorize_dealer") {
        parameters.pushKV("authorization_nonce", GetRandHash().GetHex());
        parameters.pushKV("dealer_control_key", m_control->text().trimmed().toStdString());
        parameters.pushKV("control_output", 1);
        parameters.pushKV("initial_licenses", 10);
    } else if (op == "rotate_authority") {
        parameters.pushKV("previous_policy_hash", m_info["dealer_authority_next_block_policy_hash"]);
        parameters.pushKV("next_authority_threshold", m_info["dealer_authority_threshold"]);
        if (m_next_keys->toPlainText().size() > 512) throw std::runtime_error{DealerAuthorityDialog::tr("At most five public keys are allowed").toStdString()};
        UniValue keys{UniValue::VARR};
        for (const auto& key : m_next_keys->toPlainText().split(QRegularExpression{QStringLiteral("\\s+")}, Qt::SkipEmptyParts)) keys.push_back(key.toStdString());
        parameters.pushKV("next_authority_keys", std::move(keys));
    } else {
        parameters.pushKV("dealer_id", m_dealer->text().trimmed().toStdString());
        if (op == "update_dealer") parameters.pushKV("added_licenses", m_licenses->value());
    }
    if (op == "authorize_dealer" || (op == "update_dealer" && !m_payout->text().trimmed().isEmpty())) {
        UniValue args{UniValue::VARR};
        args.push_back(m_payout->text().trimmed().toStdString());
        const auto address{call("validateaddress", std::move(args))};
        if (!address["isvalid"].get_bool()) throw std::runtime_error{DealerAuthorityDialog::tr("Invalid main-chain dealer payout address").toStdString()};
        parameters.pushKV("payout_script", address["scriptPubKey"]);
    }
    const auto proposal{build(parameters)};
    m_parameters = std::move(parameters);
    m_proposal = proposal;
    m_signatures->clear();
    m_next_signatures->clear();
    m_details->setPlainText(Json(m_proposal));
    m_verify->setEnabled(true);
    m_export->setEnabled(true);
}

void DealerAuthorityDialog::verify()
{
    if (!m_parameters.isObject()) throw std::runtime_error{DealerAuthorityDialog::tr("Prepare a proposal first").toStdString()};
    auto parameters{m_parameters};
    parameters.pushKV("authority_signatures", Signatures(m_signatures));
    if (operation() == "rotate_authority") parameters.pushKV("next_authority_signatures", Signatures(m_next_signatures));
    const auto proposal{build(parameters)};
    if (proposal["authority_hash"].get_str() != m_proposal["authority_hash"].get_str()) throw std::runtime_error{DealerAuthorityDialog::tr("Authority proposal changed").toStdString()};
    m_proposal = proposal;
    m_details->setPlainText(Json(m_proposal));
#ifdef ENABLE_WALLET
    m_submit->setEnabled(m_wallet && m_proposal["authority_complete"].get_bool());
#endif
}

void DealerAuthorityDialog::exportProposal()
{
    if (!m_parameters.isObject()) throw std::runtime_error{DealerAuthorityDialog::tr("Prepare a proposal first").toStdString()};
    // Revalidate sequence and policy before exporting, without trusting old UI state.
    verify();
    UniValue document{UniValue::VOBJ};
    document.pushKV("format", "kronein-dealer-authority-v1");
    UniValue genesis_args{UniValue::VARR};
    genesis_args.push_back(0);
    document.pushKV("main_genesis_hash", call("getblockhash", std::move(genesis_args)));
    document.pushKV("operation", operation());
    document.pushKV("parameters", m_parameters);
    document.pushKV("proposal", m_proposal);
    const auto filename{QFileDialog::getSaveFileName(this, tr("Export Authority Proposal"), {}, tr("JSON files (*.json)"))};
    if (filename.isEmpty()) return;
    QSaveFile file{filename};
    const auto bytes{Json(document).toUtf8()};
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
        throw std::runtime_error{file.errorString().toStdString()};
    }
}

#ifdef ENABLE_WALLET
void DealerAuthorityDialog::setWalletModel(WalletModel* wallet)
{
    m_wallet = wallet;
    m_submit->setEnabled(false);
}

void DealerAuthorityDialog::submit()
{
    verify();
    if (!m_wallet || !m_proposal["authority_complete"].get_bool()) throw std::runtime_error{DealerAuthorityDialog::tr("A wallet and all authority quorums are required").toStdString()};
    const QPointer<WalletModel> wallet{m_wallet};
    const auto uri{"/wallet/" + QUrl::toPercentEncoding(wallet->getWalletName()).toStdString()};
    UniValue outputs{UniValue::VARR};
    UniValue data_output{UniValue::VOBJ};
    data_output.pushKV("data", m_proposal["data"]);
    outputs.push_back(std::move(data_output));
    const bool authorize{operation() == "authorize_dealer"};
    if (authorize) {
        UniValue args{UniValue::VARR};
        args.push_back("5120" + m_parameters["dealer_control_key"].get_str());
        const auto script{call("decodescript", std::move(args))};
        UniValue output{UniValue::VOBJ};
        output.pushKV(script["address"].get_str(), UniValue{UniValue::VNUM, "0.00001000"});
        outputs.push_back(std::move(output));
    }
    UniValue options{UniValue::VOBJ};
    options.pushKV("changePosition", outputs.size());
    UniValue funding_args{UniValue::VARR};
    funding_args.push_back(UniValue{UniValue::VARR});
    funding_args.push_back(std::move(outputs));
    funding_args.push_back(0);
    funding_args.push_back(std::move(options));
    const auto funded{call("walletcreatefundedpsbt", std::move(funding_args), uri)};
    QMessageBox confirmation{QMessageBox::Warning, tr("Confirm Authority Operation"),
        tr("Broadcast %1 on the main chain?\n\nMain-chain fee: %2 KNE\nDealer control output: %3 KNE\n\nReview the complete proposal below. Revocation permanently disables future sales. Authority rotation requires both quorums and activates after 144 blocks.")
            .arg(QString::fromStdString(operation()), QString::fromStdString(funded["fee"].getValStr()), authorize ? QStringLiteral("0.00001000") : QStringLiteral("0")),
        QMessageBox::Yes | QMessageBox::Cancel, this};
    confirmation.setTextFormat(Qt::PlainText);
    confirmation.setDetailedText(Json(m_proposal));
    confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) return;
    if (!wallet) throw std::runtime_error{DealerAuthorityDialog::tr("The selected wallet is no longer available").toStdString()};
    verify();
    if (!m_proposal["authority_complete"].get_bool()) throw std::runtime_error{DealerAuthorityDialog::tr("Authority quorum is incomplete").toStdString()};
    const auto unlock{wallet->requestUnlock()};
    if (!unlock.isValid()) return;
    UniValue sign_args{UniValue::VARR};
    sign_args.push_back(funded["psbt"]);
    const auto signed_psbt{call("walletprocesspsbt", std::move(sign_args), uri)};
    UniValue finalize_args{UniValue::VARR};
    finalize_args.push_back(signed_psbt["psbt"]);
    const auto finalized{call("finalizepsbt", std::move(finalize_args))};
    if (!finalized["complete"].get_bool()) throw std::runtime_error{DealerAuthorityDialog::tr("Wallet transaction signatures are incomplete").toStdString()};
    UniValue send_args{UniValue::VARR};
    send_args.push_back(finalized["hex"]);
    const auto txid{call("sendrawtransaction", std::move(send_args))};
    QMessageBox::information(this, tr("Authority Operation Submitted"), QString::fromStdString(txid.get_str()));
    refresh();
}
#endif
