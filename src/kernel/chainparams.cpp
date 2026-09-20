// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chain.h>
#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/log.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <map>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace util::hex_literals;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * The network-specific overload below supplies Kronein's timestamp and
 * provably unspendable output.
 */
static CBlock CreateGenesisBlock(const char* network, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const std::string timestamp{strprintf("Kronein %s 19/Sep/2026 - RandomX v2 proof of work", network)};
    const std::string commitment{"Kronein genesis output - provably unspendable"};
    const CScript genesis_output_script = CScript() << OP_RETURN << std::vector<unsigned char>{commitment.begin(), commitment.end()};
    return CreateGenesisBlock(timestamp.c_str(), genesis_output_script, nTime, nNonce, nBits, nVersion, genesisReward);
}

static Consensus::Params::RandomXParams RandomXParameters(std::string_view domain, bool fixed_seed = false)
{
    Consensus::Params::RandomXParams params;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size())
        .Finalize(params.bootstrap_key.data());
    params.fixed_seed = fixed_seed;
    return params;
}

static Consensus::Params::ASERTParams ASERTParameters(const CBlock& genesis, int64_t target_spacing)
{
    return Consensus::Params::ASERTParams{
        .enabled = true,
        .anchor_height = 0,
        .anchor_bits = genesis.nBits,
        // Model a virtual parent one ideal interval before genesis. This keeps
        // the first post-genesis target equal to the genesis target.
        .anchor_parent_time = genesis.GetBlockTime() - target_spacing,
        .half_life = 2 * 24 * 60 * 60,
    };
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.randomx = RandomXParameters("Kronein/RandomX/v2/mainnet/bootstrap");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.enforce_timestamp_monotonicity = true;
        consensus.fPowNoRetargeting = false;
        consensus.defaultAssumeValid = uint256{};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        // First four bytes of SHA256("Kronein P2P mainnet magic 2").
        pchMessageStart[0] = 0xa3;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0xcf;
        pchMessageStart[3] = 0xf8;
        nDefaultPort = 26762;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock("mainnet", 1789776000, 3636, 0x1f00ffff, 1, 50 * COIN);
        consensus.asert = ASERTParameters(genesis, consensus.nPowTargetSpacing);
        consensus.nMinimumChainWork = ArithToUint256(GetBlockProof(genesis));
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(CheckProofOfWork(genesis, consensus));
        assert(consensus.hashGenesisBlock == uint256{"d79a7c8037d9e67d1aa7fc8ea321da88b8edf99b6a5fd7ab5fbfee2751885ad9"});
        assert(genesis.hashMerkleRoot == uint256{"ee1e466a37851f03f38481dd281b38a0ae273b0ac305b793ced40cd249cc94ee"});
        assert(GetSerializeSize(static_cast<const CBlockHeader&>(genesis)) == 80);

        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 0xb4);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x01, 0x87, 0x6a, 0xbe}; // Kpub
        base58Prefixes[EXT_SECRET_KEY] = {0x01, 0x87, 0x66, 0x84}; // Kprv

        bech32_hrp = "kne";

        vFixedSeeds.assign(chainparams_seed_main, chainparams_seed_main + sizeof(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        chainTxData = ChainTxData{};

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 641,
            .redownload_buffer_size = 15218, // 15218/641 = ~23.7 commitments
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.randomx = RandomXParameters("Kronein/RandomX/v2/testnet4/bootstrap");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.enforce_timestamp_monotonicity = true;
        consensus.fPowNoRetargeting = false;

        consensus.defaultAssumeValid = uint256{};

        // First four bytes of SHA256("Kronein P2P testnet4 magic 2").
        pchMessageStart[0] = 0xe9;
        pchMessageStart[1] = 0x9d;
        pchMessageStart[2] = 0x8b;
        pchMessageStart[3] = 0xa2;
        nDefaultPort = 36762;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock("testnet4", 1789776000, 92258, 0x1f00ffff, 1, 50 * COIN);
        consensus.asert = ASERTParameters(genesis, consensus.nPowTargetSpacing);
        consensus.nMinimumChainWork = ArithToUint256(GetBlockProof(genesis));
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(CheckProofOfWork(genesis, consensus));
        assert(consensus.hashGenesisBlock == uint256{"c81c93beedf92bb04515d8981f16a3e28337d072f6f1b8b2177073cbb121bfdc"});
        assert(genesis.hashMerkleRoot == uint256{"afa5478a2505eb78f1a0b45b391170bb08059c0d0ff97e12950d7bae18e331a5"});
        assert(GetSerializeSize(static_cast<const CBlockHeader&>(genesis)) == 80);

        vFixedSeeds.clear();
        vSeeds.clear();
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 0xf1);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x58, 0xff, 0xab, 0x38}; // Ktpub
        base58Prefixes[EXT_SECRET_KEY] = {0x58, 0xff, 0xa6, 0xfe}; // Ktprv

        bech32_hrp = "tkne";

        vFixedSeeds.assign(chainparams_seed_testnet4, chainparams_seed_testnet4 + sizeof(chainparams_seed_testnet4));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        chainTxData = ChainTxData{};

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 606,
            .redownload_buffer_size = 16092, // 16092/606 = ~26.6 commitments
        };
    }
};

/**
 * Signet: test network with a P2TR block-authentication challenge.
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            bin = "512096f445564af704e1fbbbb462124c15080958ac19ffb12693a6c9ab68d313811e"_hex_v_u8;
        } else {
            bin = *options.challenge;
            LogInfo("Signet with challenge %s", HexStr(bin));
        }

        if (!CScript{bin.begin(), bin.end()}.IsPayToTaproot()) {
            throw std::runtime_error("Signet challenge must be a P2TR scriptPubKey.");
        }

        consensus.defaultAssumeValid = uint256{};
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;
        chainTxData = ChainTxData{};

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.enforce_timestamp_monotonicity = true;
        consensus.fPowNoRetargeting = false;
        consensus.randomx = RandomXParameters("Kronein/RandomX/v2/signet/bootstrap");
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 46762;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock("signet", 1789776000, 4, 0x207fffff, 1, 50 * COIN);
        consensus.asert = ASERTParameters(genesis, consensus.nPowTargetSpacing);
        consensus.nMinimumChainWork = ArithToUint256(GetBlockProof(genesis));
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(CheckProofOfWork(genesis, consensus));
        assert(consensus.hashGenesisBlock == uint256{"70839a886fd128e4d6ec2de17bd0786bbf10b1184aa8ba06fc43de9cf3f096ad"});
        assert(genesis.hashMerkleRoot == uint256{"b206dec2776def7418f69919ed312ccef711ea94030f895f1c3658b5a9fe5207"});
        assert(GetSerializeSize(static_cast<const CBlockHeader&>(genesis)) == 80);

        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 0xf2);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x58, 0xea, 0xe0, 0xa4}; // Kspub
        base58Prefixes[EXT_SECRET_KEY] = {0x58, 0xea, 0xdc, 0x6a}; // Ksprv

        bech32_hrp = "skne";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 620,
            .redownload_buffer_size = 15724, // 15724/620 = ~25.4 commitments
        };
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.randomx = RandomXParameters("Kronein/RandomX/v2/regtest/fixed-seed", /*fixed_seed=*/true);
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.enforce_timestamp_monotonicity = false;
        consensus.fPowNoRetargeting = true;
        if (opts.chain_registry) consensus.chain_registry = *opts.chain_registry;

        consensus.defaultAssumeValid = uint256{};

        // First four bytes of SHA256("Kronein P2P regtest magic 6").
        pchMessageStart[0] = 0xe0;
        pchMessageStart[1] = 0xf9;
        pchMessageStart[2] = 0xab;
        pchMessageStart[3] = 0xb0;
        nDefaultPort = 56762;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock("regtest", 1789776000, 1, 0x207fffff, 1, 50 * COIN);
        consensus.nMinimumChainWork = ArithToUint256(GetBlockProof(genesis));
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(CheckProofOfWork(genesis, consensus));
        assert(consensus.hashGenesisBlock == uint256{"a55bf2cd9513e5203827b029e15153769d596b0ad29e6ebca232eaba07c95f73"});
        assert(genesis.hashMerkleRoot == uint256{"ad0a917028b6f38fa62dde00a12c869db1ebed1c78e45db36fcc1297b79c7516"});
        assert(GetSerializeSize(static_cast<const CBlockHeader&>(genesis)) == 80);

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        m_assumeutxo_data = {
            {   // For use by unit tests
                .height = 110,
                .muhash = AssumeutxoHash{uint256{"f78069a53b677d42236b556d5ca647908c09fbad54b7ee5be5da44d9d227560b"}},
                .m_chain_tx_count = 111,
                .blockhash = uint256{"6c3c539ac211222952482af5ef7793ae643a504a46d05d0dcf4d3ddfaf600058"},
            },
            {
                // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                .height = 200,
                .muhash = AssumeutxoHash{uint256{"93e2b3bf0ed8f9e2bfcdfecc0ca97eeefbd97f252c7a06784775921c42ff9de9"}},
                .m_chain_tx_count = 201,
                .blockhash = uint256{"8d88d1645a7582bce4135b98a59212141fb4a0884122717822b1abf3663cc94b"},
            },
            {
                // For use by test/functional/feature_assumeutxo.py and test/functional/tool_kronein_chainstate.py
                .height = 299,
                .muhash = AssumeutxoHash{uint256{"66debd38e54a51cc4de4f48bd177985ae7dbce80b978754e09ba87cf10262ee5"}},
                .m_chain_tx_count = 334,
                .blockhash = uint256{"2d4d7817926b3e937e319f69889c2e748c1c496aa9a707cf6256e8e7011a8b4f"},
            },
        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0.001, // Set a non-zero rate to make it testable
        };

        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 0xf3);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x58, 0xd6, 0x16, 0x10}; // Krpub
        base58Prefixes[EXT_SECRET_KEY] = {0x58, 0xd6, 0x11, 0xd6}; // Krprv

        bech32_hrp = "rkne";

        // Copied from Testnet4.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 275,
            .redownload_buffer_size = 7017, // 7017/275 = ~25.5 commitments
        };
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
