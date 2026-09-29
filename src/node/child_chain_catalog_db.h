// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_CHILD_CHAIN_CATALOG_DB_H
#define BITCOIN_NODE_CHILD_CHAIN_CATALOG_DB_H

#include <chainregistry/child_template.h>
#include <dbwrapper.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace node {

inline constexpr uint8_t CHILD_CHAIN_CATALOG_DB_VERSION{2};
inline constexpr uint8_t CHILD_CHAIN_CATALOG_ENTRY_VERSION{2};

struct ChildChainCatalogEntry {
    uint8_t version{CHILD_CHAIN_CATALOG_ENTRY_VERSION};
    chainregistry::ChainId chain_id;
    COutPoint registration_anchor;
    chainregistry::ChainManifest manifest;

    SERIALIZE_METHODS(ChildChainCatalogEntry, obj)
    {
        READWRITE(obj.version,
                  obj.chain_id,
                  obj.registration_anchor,
                  obj.manifest);
    }

    friend bool operator==(const ChildChainCatalogEntry&, const ChildChainCatalogEntry&) = default;
};

struct ChildChainCatalogState {
    uint8_t version{CHILD_CHAIN_CATALOG_DB_VERSION};
    uint256 main_genesis_hash;
    uint64_t record_count{0};

    SERIALIZE_METHODS(ChildChainCatalogState, obj)
    {
        READWRITE(obj.version, obj.main_genesis_hash, obj.record_count);
    }

    friend bool operator==(const ChildChainCatalogState&, const ChildChainCatalogState&) = default;
};

enum class ChildChainCatalogLoadError : uint8_t {
    NONE,
    STATE_DECODE_FAILED,
    ORPHANED_DATA,
    UNSUPPORTED_VERSION,
    WRONG_MAIN_GENESIS,
    RECORD_KEY_DECODE_FAILED,
    RECORD_DECODE_FAILED,
    INVALID_RECORD,
    RECORD_KEY_MISMATCH,
    DUPLICATE_RECORD,
    RECORD_COUNT_MISMATCH,
    DATABASE_WRITE_FAILED,
};

struct ChildChainCatalogLoadResult {
    ChildChainCatalogLoadError error{ChildChainCatalogLoadError::NONE};
    std::vector<chainregistry::ReferenceChildDefinition> definitions;
    bool initialized{false};

    bool IsValid() const { return error == ChildChainCatalogLoadError::NONE; }
};

/** Persistent local copy of complete, validated child manifests. */
class ChildChainCatalogDB
{
private:
    CDBWrapper m_db;
    const uint256 m_main_genesis_hash;

public:
    ChildChainCatalogDB(const DBParams& params,
                        const uint256& main_genesis_hash)
        : m_db{params}, m_main_genesis_hash{main_genesis_hash}
    {
    }

    ChildChainCatalogLoadResult Load() const;
    bool WriteInitialState(bool sync = false);
    bool WriteDefinition(
        const chainregistry::ReferenceChildDefinition& definition,
        uint64_t previous_record_count,
        bool sync = false);
    bool EraseDefinition(const chainregistry::ChainId& chain_id,
                         uint64_t previous_record_count,
                         bool sync = false);
};

} // namespace node

#endif // BITCOIN_NODE_CHILD_CHAIN_CATALOG_DB_H
