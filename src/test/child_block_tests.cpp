// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_block.h>

#include <addresstype.h>
#include <chainparams.h>
#include <chainregistry/child_sighash.h>
#include <coins.h>
#include <consensus/chainregistry.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <key.h>
#include <pow.h>
#include <primitives/deposit.h>
#include <script/interpreter.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace {

const COutPoint REGISTRATION_ANCHOR{
    Txid{"1111111111111111111111111111111111111111111111111111111111111111"},
    1};
const chainregistry::MetadataHash METADATA_HASH{
    "4444444444444444444444444444444444444444444444444444444444444444"};

struct ChildBlockSetup : BasicTestingSetup {
    ChildBlockSetup()
        : BasicTestingSetup{ChainType::REGTEST}
    {
    }
};

CKey TestKey(uint8_t discriminator)
{
    std::array<unsigned char, 32> secret{};
    secret.back() = discriminator;
    CKey key;
    key.Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
    return key;
}

chainregistry::ReferenceChildDefinition Definition()
{
    const auto result{chainregistry::BuildReferenceChildDefinition(
        Params().GetConsensus().hashGenesisBlock,
        REGISTRATION_ANCHOR,
        chainregistry::MakeReferenceChildSpec({}),
        METADATA_HASH)};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
}

chainregistry::ChainRecord Record(
    const chainregistry::ReferenceChildDefinition& definition)
{
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = definition.chain_id,
        .manifest_hash = definition.manifest_hash,
        .template_id = chainregistry::REFERENCE_CHILD_TEMPLATE_ID,
        .template_version = chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION,
        .control_outpoint = COutPoint{
            Txid{"3333333333333333333333333333333333333333333333333333333333333333"},
            0},
        .metadata_hash = METADATA_HASH,
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 0,
        .updated_height = 0,
    };
}

CMutableTransaction ChildCoinbase(int height,
                                  CAmount reward,
                                  const XOnlyPubKey& recipient)
{
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig =
        CScript{} << height << std::vector<unsigned char>{0};
    coinbase.vin.front().scriptWitness.stack = {
        std::vector<unsigned char>(32)};
    if (reward != 0) {
        coinbase.vout.emplace_back(
            reward,
            GetScriptForDestination(WitnessV1Taproot{recipient}));
    }
    return coinbase;
}

CBlock ChildBlock(const CBlockIndex& parent,
                  CAmount reward,
                  const XOnlyPubKey& recipient,
                  std::vector<CTransactionRef> transactions = {})
{
    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = parent.GetBlockHash();
    block.nTime = parent.nTime + 1;
    block.nBits = 0;
    block.nNonce = 0;
    block.vtx.push_back(MakeTransactionRef(
        ChildCoinbase(parent.nHeight + 1, reward, recipient)));
    block.vtx.insert(block.vtx.end(),
                     transactions.begin(),
                     transactions.end());

    const std::vector<unsigned char>& reserved{
        block.vtx.front()->vin.front().scriptWitness.stack.front()};
    uint256 commitment{BlockWitnessMerkleRoot(block)};
    CHash256().Write(commitment).Write(reserved).Finalize(commitment);
    std::vector<unsigned char> payload{0xaa, 0x21, 0xa9, 0xed};
    payload.insert(payload.end(), commitment.begin(), commitment.end());

    CMutableTransaction coinbase{*block.vtx.front()};
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
    block.vtx.front() = MakeTransactionRef(std::move(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

struct ChildState {
    chainregistry::ReferenceChildDefinition definition;
    CBlockIndex genesis;
    CCoinsView base;
    CCoinsViewCache coins;
    chainregistry::DepositImportState imports;

    ChildState()
        : definition{Definition()},
          genesis{CBlockHeader{}},
          coins{&base, /*deterministic=*/true},
          imports{definition.chain_id,
                  definition.parameters.deposit_maturity}
    {
        genesis.phashBlock = &definition.genesis_hash;
        genesis.nHeight = 0;
        genesis.nTime = Params().GenesisBlock().nTime;
        genesis.nTimeMax = genesis.nTime;
        coins.SetBestBlock(definition.genesis_hash);
    }
};

CBlockHeader MineMainHeader(const CBlockIndex& parent,
                            const Consensus::Params& params,
                            uint32_t discriminator)
{
    CBlockHeader header;
    header.nVersion = CBlockHeader::CURRENT_VERSION;
    header.hashPrevBlock = parent.GetBlockHash();
    header.hashMerkleRoot = uint256{static_cast<uint8_t>(discriminator)};
    header.nTime = parent.nTime + 1;
    header.nBits = GetNextWorkRequired(&parent, &header, params);
    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        header,
        *seed,
        params,
        max_tries,
        /*threads=*/1,
        /*use_full_memory=*/false));
    return header;
}

chainregistry::DepositProof DepositProof(
    CBlock& block,
    const CBlockIndex& parent,
    const Consensus::Params& params,
    const chainregistry::ReferenceChildDefinition& definition,
    const XOnlyPubKey& recipient)
{
    const auto record{Record(definition)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig = CScript{} << 1 << OP_0;
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));

    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint{
        Txid{"5555555555555555555555555555555555555555555555555555555555555555"},
        0});
    funding.vout.emplace_back(
        50'000,
        chainregistry::BuildFundScript({
            .chain_id = definition.chain_id,
            .recipient_type = chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT,
            .recipient = {recipient.begin(), recipient.end()},
        }));

    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = parent.GetBlockHash();
    block.nTime = parent.nTime + 1;
    block.nBits = GetNextWorkRequired(&parent, &block, params);
    block.vtx = {
        MakeTransactionRef(coinbase), MakeTransactionRef(funding)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        block,
        *seed,
        params,
        max_tries,
        /*threads=*/1,
        /*use_full_memory=*/false));

    return {
        .main_genesis_hash = params.hashGenesisBlock,
        .block_height = static_cast<uint32_t>(parent.nHeight + 1),
        .block_header = block,
        .funding_transaction = funding,
        .funding_vout = 0,
        .transaction_index = 1,
        .transaction_merkle_branch = TransactionMerklePath(block, 1),
        .coinbase_transaction = coinbase,
        .coinbase_merkle_branch = TransactionMerklePath(block, 0),
        .chain_record = record,
        .registry_proof = *registry.GetInclusionProof(definition.chain_id),
    };
}

CMutableTransaction SignedSpend(
    const COutPoint& prevout,
    const CTxOut& spent_output,
    CAmount output_value,
    const CKey& key,
    const chainregistry::ChainId& signing_chain)
{
    const XOnlyPubKey pubkey{key.GetPubKey()};
    CMutableTransaction transaction;
    transaction.vin.emplace_back(prevout);
    transaction.vout.emplace_back(
        output_value,
        GetScriptForDestination(WitnessV1Taproot{pubkey}));

    PrecomputedTransactionData txdata;
    txdata.Init(transaction, std::vector<CTxOut>{spent_output});
    ScriptExecutionData execution_data;
    execution_data.m_annex_init = true;
    execution_data.m_annex_present = false;
    uint256 base_sighash;
    BOOST_REQUIRE(SignatureHashSchnorr(
        base_sighash,
        execution_data,
        transaction,
        0,
        SIGHASH_DEFAULT,
        SigVersion::TAPROOT,
        txdata,
        MissingDataBehavior::FAIL));
    const auto child_sighash{
        chainregistry::ComputeReferenceChildSignatureHash(
            signing_chain, base_sighash)};
    BOOST_REQUIRE(child_sighash.has_value());
    std::vector<unsigned char> signature(64);
    BOOST_REQUIRE(key.SignSchnorr(
        *child_sighash, signature, /*merkle_root=*/nullptr, /*aux=*/{}));
    transaction.vin.front().scriptWitness.stack = {std::move(signature)};
    return transaction;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_block_tests, ChildBlockSetup)

BOOST_AUTO_TEST_CASE(connects_and_disconnects_zero_subsidy_block)
{
    ChildState state;
    chainregistry::MainHeaderChain main_headers{Params().GetConsensus()};
    BOOST_REQUIRE(main_headers.Initialize(Params().GenesisBlock()).IsValid());
    const CKey key{TestKey(1)};
    const CBlock block{ChildBlock(
        state.genesis, 0, XOnlyPubKey{key.GetPubKey()})};

    const auto connected{chainregistry::ConnectReferenceChildBlock(
        block,
        state.genesis,
        block.nTime,
        state.definition,
        main_headers,
        state.coins,
        state.imports)};
    BOOST_REQUIRE(connected.IsValid());
    BOOST_REQUIRE(connected.undo.has_value());
    BOOST_CHECK_EQUAL(connected.total_fees, 0);
    BOOST_CHECK(state.coins.GetBestBlock() == block.GetHash());
    BOOST_CHECK_EQUAL(state.imports.Size(), 0U);

    const auto disconnected{chainregistry::DisconnectReferenceChildBlock(
        block, *connected.undo, state.coins, state.imports)};
    BOOST_CHECK(disconnected.IsValid());
    BOOST_CHECK(state.coins.GetBestBlock() == state.definition.genesis_hash);
    BOOST_CHECK_EQUAL(state.imports.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(rejects_subsidy_and_header_or_witness_malleation_atomically)
{
    ChildState state;
    chainregistry::MainHeaderChain main_headers{Params().GetConsensus()};
    BOOST_REQUIRE(main_headers.Initialize(Params().GenesisBlock()).IsValid());
    const XOnlyPubKey recipient{TestKey(2).GetPubKey()};

    CBlock subsidy{ChildBlock(state.genesis, 1, recipient)};
    BOOST_CHECK(chainregistry::ConnectReferenceChildBlock(
                    subsidy,
                    state.genesis,
                    subsidy.nTime,
                    state.definition,
                    main_headers,
                    state.coins,
                    state.imports)
                    .error ==
                chainregistry::ReferenceChildBlockError::COINBASE_PAYS_TOO_MUCH);

    CBlock local_pow{subsidy};
    local_pow.nBits = 0x207fffff;
    BOOST_CHECK(chainregistry::ConnectReferenceChildBlock(
                    local_pow,
                    state.genesis,
                    local_pow.nTime,
                    state.definition,
                    main_headers,
                    state.coins,
                    state.imports)
                    .error ==
                chainregistry::ReferenceChildBlockError::INVALID_HEADER);

    CBlock witness{ChildBlock(state.genesis, 0, recipient)};
    CMutableTransaction coinbase{*witness.vtx.front()};
    coinbase.vin.front().scriptWitness.stack.front().front() = 1;
    witness.vtx.front() = MakeTransactionRef(std::move(coinbase));
    witness.hashMerkleRoot = BlockMerkleRoot(witness);
    BOOST_CHECK(chainregistry::ConnectReferenceChildBlock(
                    witness,
                    state.genesis,
                    witness.nTime,
                    state.definition,
                    main_headers,
                    state.coins,
                    state.imports)
                    .error ==
                chainregistry::ReferenceChildBlockError::INVALID_WITNESS_COMMITMENT);

    BOOST_CHECK(state.coins.GetBestBlock() == state.definition.genesis_hash);
    BOOST_CHECK_EQUAL(state.imports.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(applies_domain_separated_spends_and_fees)
{
    ChildState state;
    chainregistry::MainHeaderChain main_headers{Params().GetConsensus()};
    BOOST_REQUIRE(main_headers.Initialize(Params().GenesisBlock()).IsValid());
    const CKey key{TestKey(3)};
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const CTxOut seeded_output{
        50'000,
        GetScriptForDestination(WitnessV1Taproot{pubkey})};
    const COutPoint seeded{
        Txid{"7777777777777777777777777777777777777777777777777777777777777777"},
        0};
    state.coins.AddCoin(
        seeded, Coin{seeded_output, 0, /*coinbase=*/false}, false);

    const chainregistry::ChainId other_chain{
        "8888888888888888888888888888888888888888888888888888888888888888"};
    const CTransactionRef wrong_spend{MakeTransactionRef(SignedSpend(
        seeded, seeded_output, 49'000, key, other_chain))};
    const CBlock wrong_block{
        ChildBlock(state.genesis, 1'000, pubkey, {wrong_spend})};
    const auto rejected{chainregistry::ConnectReferenceChildBlock(
        wrong_block,
        state.genesis,
        wrong_block.nTime,
        state.definition,
        main_headers,
        state.coins,
        state.imports)};
    BOOST_CHECK(rejected.error ==
                chainregistry::ReferenceChildBlockError::SCRIPT_REJECTED);
    BOOST_CHECK_EQUAL(rejected.script_error, SCRIPT_ERR_SCHNORR_SIG);
    BOOST_CHECK(state.coins.HaveCoin(seeded));

    const CTransactionRef spend{MakeTransactionRef(SignedSpend(
        seeded,
        seeded_output,
        49'000,
        key,
        state.definition.chain_id))};
    const CBlock block{ChildBlock(state.genesis, 1'000, pubkey, {spend})};
    const auto connected{chainregistry::ConnectReferenceChildBlock(
        block,
        state.genesis,
        block.nTime,
        state.definition,
        main_headers,
        state.coins,
        state.imports)};
    BOOST_REQUIRE(connected.IsValid());
    BOOST_CHECK_EQUAL(connected.total_fees, 1'000);
    BOOST_CHECK(!state.coins.HaveCoin(seeded));
    BOOST_CHECK(state.coins.HaveCoin(COutPoint{spend->GetHash(), 0}));

    BOOST_REQUIRE(connected.undo.has_value());
    BOOST_REQUIRE(chainregistry::DisconnectReferenceChildBlock(
        block, *connected.undo, state.coins, state.imports).IsValid());
    BOOST_CHECK(state.coins.HaveCoin(seeded));
    BOOST_CHECK(!state.coins.HaveCoin(COutPoint{spend->GetHash(), 0}));
}

BOOST_AUTO_TEST_CASE(imports_mature_deposit_once_and_reverses_supply)
{
    ChildState state;
    const auto& params{Params().GetConsensus()};
    chainregistry::MainHeaderChain main_headers{params};
    BOOST_REQUIRE(main_headers.Initialize(Params().GenesisBlock()).IsValid());
    const CBlockIndex* main_parent{
        main_headers.Find(params.hashGenesisBlock)};
    BOOST_REQUIRE(main_parent);
    const CKey key{TestKey(4)};
    const XOnlyPubKey recipient{key.GetPubKey()};

    CBlock deposit_block;
    const auto proof{DepositProof(
        deposit_block, *main_parent, params, state.definition, recipient)};
    BOOST_REQUIRE(main_headers.AddHeader(
        deposit_block, deposit_block.nTime).IsValid());
    for (uint32_t confirmation{1};
         confirmation < state.definition.parameters.deposit_maturity;
         ++confirmation) {
        const CBlockIndex* tip{main_headers.Tip()};
        BOOST_REQUIRE(tip);
        const CBlockHeader header{MineMainHeader(
            *tip, params, confirmation)};
        BOOST_REQUIRE(main_headers.AddHeader(header, header.nTime).IsValid());
    }
    BOOST_CHECK_EQUAL(
        main_headers.GetStatus(deposit_block.GetHash()).confirmations,
        state.definition.parameters.deposit_maturity);

    const auto built{chainregistry::BuildReferenceChildImportTransaction(
        proof, state.definition)};
    BOOST_REQUIRE(built.IsValid());
    const CTransactionRef import_transaction{
        MakeTransactionRef(*built.transaction)};
    const CBlock block{ChildBlock(
        state.genesis, 0, recipient, {import_transaction})};
    const auto connected{chainregistry::ConnectReferenceChildBlock(
        block,
        state.genesis,
        block.nTime,
        state.definition,
        main_headers,
        state.coins,
        state.imports)};
    BOOST_REQUIRE(connected.IsValid());
    BOOST_REQUIRE(connected.undo.has_value());
    BOOST_CHECK_EQUAL(state.imports.Size(), 1U);
    const COutPoint imported_outpoint{import_transaction->GetHash(), 0};
    BOOST_REQUIRE(state.coins.HaveCoin(imported_outpoint));
    BOOST_CHECK_EQUAL(
        state.coins.AccessCoin(imported_outpoint).out.nValue, 50'000);

    const uint256 first_hash{block.GetHash()};
    CBlockIndex first{block};
    first.phashBlock = &first_hash;
    first.pprev = &state.genesis;
    first.nHeight = 1;
    first.nTimeMax = std::max(first.nTime, state.genesis.nTimeMax);
    first.BuildSkip();
    const CBlock replay{ChildBlock(first, 0, recipient, {import_transaction})};
    const auto replayed{chainregistry::ConnectReferenceChildBlock(
        replay,
        first,
        replay.nTime,
        state.definition,
        main_headers,
        state.coins,
        state.imports)};
    BOOST_CHECK(replayed.error ==
                chainregistry::ReferenceChildBlockError::IMPORT_REJECTED);
    BOOST_CHECK(replayed.deposit_error ==
                chainregistry::DepositImportError::ALREADY_IMPORTED);
    BOOST_CHECK_EQUAL(state.imports.Size(), 1U);

    auto incomplete_undo{*connected.undo};
    incomplete_undo.imports.imports.clear();
    BOOST_CHECK(chainregistry::DisconnectReferenceChildBlock(
                    block, incomplete_undo, state.coins, state.imports)
                    .error ==
                chainregistry::ReferenceChildBlockError::INVALID_UNDO);
    BOOST_CHECK_EQUAL(state.imports.Size(), 1U);
    BOOST_CHECK(state.coins.HaveCoin(imported_outpoint));

    BOOST_REQUIRE(chainregistry::DisconnectReferenceChildBlock(
        block, *connected.undo, state.coins, state.imports).IsValid());
    BOOST_CHECK_EQUAL(state.imports.Size(), 0U);
    BOOST_CHECK(!state.coins.HaveCoin(imported_outpoint));
}

BOOST_AUTO_TEST_SUITE_END()
