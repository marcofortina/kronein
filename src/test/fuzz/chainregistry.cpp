// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/bmm.h>
#include <consensus/deposit_proof.h>
#include <primitives/bmm.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <optional>

FUZZ_TARGET(chainregistry_script_parsers)
{
    const CScript script{buffer.begin(), buffer.end()};

    const auto operation{chainregistry::ParseOperationScript(script)};
    if (operation) {
        const auto roundtrip{chainregistry::ParseOperationScript(
            chainregistry::BuildOperationScript(*operation.operation))};
        assert(roundtrip);
        assert(roundtrip.operation == operation.operation);
    }

    const auto fund{chainregistry::ParseFundScript(script)};
    if (fund) {
        const auto roundtrip{chainregistry::ParseFundScript(
            chainregistry::BuildFundScript(*fund.fund))};
        assert(roundtrip);
        assert(roundtrip.fund == fund.fund);
    }

    const auto anchor{chainregistry::ParseBmmAnchorScript(script)};
    if (anchor) {
        const auto roundtrip{chainregistry::ParseBmmAnchorScript(
            chainregistry::BuildBmmAnchorScript(*anchor.anchor))};
        assert(roundtrip);
        assert(roundtrip.anchor == anchor.anchor);
    }
}

FUZZ_TARGET(chainregistry_transaction_parsers)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto mutable_tx{ConsumeDeserializable<CMutableTransaction>(
        provider, TX_BASE)};
    if (!mutable_tx) return;

    const CTransaction tx{*mutable_tx};
    (void)chainregistry::ExtractTransactionOperation(
        tx, ConsumeMoney(provider));
    (void)chainregistry::ExtractTransactionFunds(tx);
    (void)chainregistry::ExtractTransactionBmmAnchor(tx);
}

FUZZ_TARGET(chainregistry_proof_parsers)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const uint256 main_genesis{ConsumeUInt256(provider)};
    const std::optional<chainregistry::ChainId> child_chain{
        provider.ConsumeBool()
            ? std::optional{chainregistry::ChainId::FromUint256(
                  ConsumeUInt256(provider))}
            : std::nullopt};

    if (const auto proof{ConsumeDeserializable<chainregistry::DepositProof>(
            provider)}) {
        (void)chainregistry::ValidateDepositProofStructure(
            *proof, main_genesis, child_chain);
    }
    if (const auto proof{ConsumeDeserializable<chainregistry::BmmAnchorProof>(
            provider)}) {
        (void)chainregistry::ValidateBmmAnchorProofStructure(
            *proof, main_genesis, child_chain);
    }
}
