// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_UTXO_SNAPSHOT_H
#define BITCOIN_NODE_UTXO_SNAPSHOT_H

#include <consensus/chainregistry.h>
#include <kernel/chainparams.h>
#include <kernel/cs_main.h>
#include <kernel/messagestartchars.h>
#include <primitives/dealerauthority.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/result.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

class CBlockHeader;

// UTXO set snapshot magic bytes
static constexpr std::array<uint8_t, 5> SNAPSHOT_MAGIC_BYTES = {'u', 't', 'x', 'o', 0xff};
static constexpr std::array<uint8_t, 5> SNAPSHOT_REGISTRY_MAGIC_BYTES = {'k', 'r', 'e', 'g', 0xff};

class Chainstate;

namespace node {
inline constexpr uint8_t REGISTRY_SNAPSHOT_VERSION{4};
inline constexpr uint64_t MAX_REGISTRY_SNAPSHOT_RECORDS{1'000'000};
inline constexpr uint64_t MAX_REGISTRY_SNAPSHOT_DEALERS{1'000'000};
inline constexpr uint64_t MAX_REGISTRY_SNAPSHOT_MERKLE_BRANCH{32};

/**
 * Authenticated child-chain registry trailer appended after the UTXO entries.
 * The coinbase and its Merkle branch bind registry_root to the snapshot base
 * header without requiring the complete base block to be available locally.
 */
struct RegistrySnapshot {
    uint8_t version{REGISTRY_SNAPSHOT_VERSION};
    uint256 base_blockhash;
    uint256 registry_root;
    std::vector<chainregistry::ChainRecord> records;
    std::vector<chainregistry::DealerRecord> dealers;
    uint64_t authority_sequence{0};
    chainregistry::DealerAuthorityTransition authority_transition{};
    CMutableTransaction coinbase;
    std::vector<uint256> coinbase_merkle_branch;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (records.size() > MAX_REGISTRY_SNAPSHOT_RECORDS) {
            throw std::ios_base::failure("Child chain registry snapshot has too many records.");
        }
        if (dealers.size() > MAX_REGISTRY_SNAPSHOT_DEALERS) {
            throw std::ios_base::failure("Child chain registry snapshot has too many dealers.");
        }
        if (coinbase_merkle_branch.size() > MAX_REGISTRY_SNAPSHOT_MERKLE_BRANCH) {
            throw std::ios_base::failure("Child chain registry snapshot Merkle branch is too long.");
        }
        stream << SNAPSHOT_REGISTRY_MAGIC_BYTES;
        stream << version;
        stream << base_blockhash;
        stream << registry_root;
        WriteCompactSize(stream, records.size());
        for (const auto& record : records) stream << record;
        WriteCompactSize(stream, dealers.size());
        for (const auto& dealer : dealers) stream << dealer;
        stream << authority_sequence << authority_transition;
        stream << TX_WITH_WITNESS(coinbase);
        WriteCompactSize(stream, coinbase_merkle_branch.size());
        for (const auto& hash : coinbase_merkle_branch) stream << hash;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        std::array<uint8_t, SNAPSHOT_REGISTRY_MAGIC_BYTES.size()> magic;
        stream >> magic;
        if (magic != SNAPSHOT_REGISTRY_MAGIC_BYTES) {
            throw std::ios_base::failure("Invalid child chain registry snapshot magic bytes.");
        }
        stream >> version;
        stream >> base_blockhash;
        stream >> registry_root;

        const uint64_t record_count{ReadCompactSize(stream)};
        if (record_count > MAX_REGISTRY_SNAPSHOT_RECORDS) {
            throw std::ios_base::failure("Child chain registry snapshot has too many records.");
        }
        records.resize(record_count);
        for (auto& record : records) stream >> record;

        const uint64_t dealer_count{ReadCompactSize(stream)};
        if (dealer_count > MAX_REGISTRY_SNAPSHOT_DEALERS) {
            throw std::ios_base::failure("Child chain registry snapshot has too many dealers.");
        }
        dealers.resize(dealer_count);
        for (auto& dealer : dealers) stream >> dealer;
        stream >> authority_sequence >> authority_transition;

        stream >> TX_WITH_WITNESS(coinbase);
        const uint64_t branch_size{ReadCompactSize(stream)};
        if (branch_size > MAX_REGISTRY_SNAPSHOT_MERKLE_BRANCH) {
            throw std::ios_base::failure("Child chain registry snapshot Merkle branch is too long.");
        }
        coinbase_merkle_branch.resize(branch_size);
        for (auto& hash : coinbase_merkle_branch) stream >> hash;
    }
};

util::Result<chainregistry::ChainRegistry> ValidateRegistrySnapshot(
    const RegistrySnapshot& snapshot,
    const CBlockHeader& base_header);

//! Metadata describing a serialized version of a UTXO set from which an
//! assumeutxo Chainstate can be constructed.
//! All metadata fields come from an untrusted file, so must be validated
//! before being used. Thus, new fields should be added only if needed.
class SnapshotMetadata
{
    const MessageStartChars m_network_magic;
public:
    //! The hash of the block that reflects the tip of the chain for the
    //! UTXO set contained in this snapshot.
    uint256 m_base_blockhash;


    //! The number of coins in the UTXO set contained in this snapshot. Used
    //! during snapshot load to estimate progress of UTXO set reconstruction.
    uint64_t m_coins_count = 0;

    SnapshotMetadata(
        const MessageStartChars network_magic) :
            m_network_magic(network_magic) { }
    SnapshotMetadata(
        const MessageStartChars network_magic,
        const uint256& base_blockhash,
        uint64_t coins_count) :
            m_network_magic(network_magic),
            m_base_blockhash(base_blockhash),
            m_coins_count(coins_count) { }

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        s << SNAPSHOT_MAGIC_BYTES;
        s << m_network_magic;
        s << m_base_blockhash;
        s << m_coins_count;
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read the snapshot magic bytes
        std::array<uint8_t, SNAPSHOT_MAGIC_BYTES.size()> snapshot_magic;
        s >> snapshot_magic;
        if (snapshot_magic != SNAPSHOT_MAGIC_BYTES) {
            throw std::ios_base::failure("Invalid UTXO set snapshot magic bytes.");
        }

        // Read the network magic (pchMessageStart)
        MessageStartChars message;
        s >> message;
        if (!std::equal(message.begin(), message.end(), m_network_magic.data())) {
            auto metadata_network{GetNetworkForMagic(message)};
            if (metadata_network) {
                std::string network_string{ChainTypeToString(metadata_network.value())};
                auto node_network{GetNetworkForMagic(m_network_magic)};
                std::string node_network_string{ChainTypeToString(node_network.value())};
                throw std::ios_base::failure(strprintf("The network of the snapshot (%s) does not match the network of this node (%s).", network_string, node_network_string));
            } else {
                throw std::ios_base::failure("This snapshot has been created for an unrecognized network. This could be a custom signet, a new testnet or possibly caused by data corruption.");
            }
        }

        s >> m_base_blockhash;
        s >> m_coins_count;
    }
};

//! The file in the snapshot chainstate dir which stores the base blockhash. This is
//! needed to reconstruct snapshot chainstates on init.
//!
//! Because we only allow loading a single snapshot at a time, there will only be one
//! chainstate directory with this filename present within it.
const fs::path SNAPSHOT_BLOCKHASH_FILENAME{"base_blockhash"};

//! Write out the blockhash of the snapshot base block that was used to construct
//! this chainstate. This value is read in during subsequent initializations and
//! used to reconstruct snapshot-based chainstates.
bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

//! Read the blockhash of the snapshot base block that was used to construct the
//! chainstate.
std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

//! Suffix appended to the chainstate (leveldb) dir when created based upon
//! a snapshot.
constexpr std::string_view SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot";


//! Return a path to the snapshot-based chainstate dir, if one exists.
std::optional<fs::path> FindAssumeutxoChainstateDir(const fs::path& data_dir);

} // namespace node

#endif // BITCOIN_NODE_UTXO_SNAPSHOT_H
