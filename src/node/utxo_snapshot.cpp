// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <hash.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/log.h>
#include <validation.h>

#include <cassert>
#include <cstdio>
#include <optional>
#include <span>
#include <string>

namespace node {

util::Result<chainregistry::ChainRegistry> ValidateRegistrySnapshot(
    const RegistrySnapshot& snapshot,
    const CBlockHeader& base_header)
{
    if (snapshot.version != REGISTRY_SNAPSHOT_VERSION) {
        return util::Error{Untranslated("Unsupported child chain registry snapshot version")};
    }
    if (snapshot.base_blockhash != base_header.GetHash()) {
        return util::Error{Untranslated("Child chain registry snapshot base block does not match")};
    }
    const CTransaction coinbase{snapshot.coinbase};
    if (!coinbase.IsCoinBase()) {
        return util::Error{Untranslated("Child chain registry snapshot transaction is not coinbase")};
    }
    for (size_t index{1}; index < snapshot.records.size(); ++index) {
        if (!(snapshot.records[index - 1].chain_id < snapshot.records[index].chain_id)) {
            return util::Error{Untranslated("Child chain registry snapshot records are not canonically ordered")};
        }
    }

    chainregistry::ChainRegistry registry;
    const auto load_result{registry.LoadRecords(snapshot.records)};
    if (!load_result.IsValid()) {
        return util::Error{Untranslated(strprintf(
            "Invalid child chain registry snapshot records (load error %u, record error %u)",
            static_cast<unsigned>(load_result.error),
            static_cast<unsigned>(load_result.record_error)))};
    }
    if (registry.ComputeRoot() != snapshot.registry_root) {
        return util::Error{Untranslated("Child chain registry snapshot root does not match its records")};
    }

    const auto commitment{chainregistry::ExtractRegistryCommitment(coinbase)};
    if (!commitment.IsValid() || !commitment.root || *commitment.root != snapshot.registry_root) {
        return util::Error{Untranslated("Child chain registry snapshot does not match its coinbase commitment")};
    }

    uint256 merkle_root{coinbase.GetHash().ToUint256()};
    for (const auto& sibling : snapshot.coinbase_merkle_branch) {
        merkle_root = Hash(merkle_root, sibling);
    }
    if (merkle_root != base_header.hashMerkleRoot) {
        return util::Error{Untranslated("Child chain registry snapshot coinbase proof does not match the base header")};
    }
    return registry;
}

bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.StoragePath();
    assert(chaindir); // Sanity check that chainstate isn't in-memory.
    const fs::path write_to = *chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    FILE* file{fsbridge::fopen(write_to, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogError("[snapshot] failed to open base blockhash file for writing: %s",
                  fs::PathToString(write_to));
        return false;
    }
    afile << *snapshot_chainstate.m_from_snapshot_blockhash;

    if (afile.fclose() != 0) {
        LogError("[snapshot] failed to close base blockhash file %s after writing",
                  fs::PathToString(write_to));
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        LogWarning("[snapshot] cannot read base blockhash: no chainstate dir "
            "exists at path %s", fs::PathToString(chaindir));
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const std::string read_from_str = fs::PathToString(read_from);

    if (!fs::exists(read_from)) {
        LogWarning("[snapshot] snapshot chainstate dir is malformed! no base blockhash file "
            "exists at path %s. Try deleting %s and calling loadtxoutset again?",
            fs::PathToString(chaindir), read_from_str);
        return std::nullopt;
    }

    uint256 base_blockhash;
    FILE* file{fsbridge::fopen(read_from, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogWarning("[snapshot] failed to open base blockhash file for reading: %s",
            read_from_str);
        return std::nullopt;
    }
    afile >> base_blockhash;

    int64_t position = afile.tell();
    afile.seek(0, SEEK_END);
    if (position != afile.tell()) {
        LogWarning("[snapshot] unexpected trailing data in %s", read_from_str);
    }
    return base_blockhash;
}

std::optional<fs::path> FindAssumeutxoChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
