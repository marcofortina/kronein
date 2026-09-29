// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_CHILD_NETWORK_MANAGER_H
#define BITCOIN_NODE_CHILD_NETWORK_MANAGER_H

#include <node/child_bandwidth.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

class CChainParams;
class CScheduler;

namespace node {

class ChainManager;

inline constexpr size_t MAX_CHILD_CONNECT_NODES{8};
inline constexpr size_t MAX_CHILD_BIND_ENDPOINTS{4};
inline constexpr size_t MAX_CHILD_BOOTSTRAP_NODES{8};
inline constexpr int MAX_CHILD_AUTOMATIC_CONNECTIONS{4};
inline constexpr int MAX_CHILD_INBOUND_CONNECTIONS{8};
inline constexpr uint64_t DEFAULT_CHILD_UPLOAD_TARGET_BYTES{8ULL << 30};
inline constexpr std::string_view DEFAULT_CHILD_UPLOAD_TARGET{"8G"};
struct ChildNetworkConfig {
    std::vector<std::string> connect;
    std::vector<std::string> bind;
    std::vector<std::string> bootstrap;
    bool discovery{false};
    bool network_active{true};
};

enum class ChildNetworkError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    ALREADY_RUNNING,
    NOT_RUNNING,
    NULL_TRANSACTION,
    TOO_MANY_ENDPOINTS,
    INVALID_ENDPOINT,
    TOO_MANY_BIND_ENDPOINTS,
    INVALID_BIND_ENDPOINT,
    TOO_MANY_BOOTSTRAP_ENDPOINTS,
    INVALID_BOOTSTRAP_ENDPOINT,
    DATA_DIRECTORY_ERROR,
    PEER_STORE_ERROR,
    CONFIG_READ_ERROR,
    CONFIG_WRITE_ERROR,
    CONFIG_INVALID,
    START_FAILED,
    NODE_ALREADY_ADDED,
    NODE_NOT_ADDED,
};

struct ChildNetworkResult {
    ChildNetworkError error{ChildNetworkError::NONE};
    std::string detail;
    size_t relayed_peers{0};

    bool IsValid() const { return error == ChildNetworkError::NONE; }
};

struct ChildNetworkStats {
    chainregistry::ChainId chain_id;
    bool running{false};
    bool network_active{false};
    size_t connections{0};
    size_t handshaken{0};
    uint64_t inbound_netgroup_rejections{0};
    size_t known_addresses{0};
    uint64_t rate_limited_requests{0};
    bool discovery{false};
    std::vector<std::string> added_nodes;
    std::vector<std::string> bind_endpoints;
    std::vector<std::string> bootstrap_nodes;
};

struct ChildNetworkInfo {
    ChildNetworkResult result;
    ChildNetworkStats stats;

    bool IsValid() const { return result.IsValid(); }
};

/** Owns one physically separate CConnman stack for every loaded child. */
class ChildNetworkManager
{
private:
    struct Network;

    ChainManager& m_chain_manager;
    const CChainParams& m_chain_params;
    CScheduler& m_scheduler;
    ChildBandwidthLimiter m_bandwidth;
    mutable Mutex m_mutex;
    std::map<chainregistry::ChainId, std::unique_ptr<Network>> m_networks
        GUARDED_BY(m_mutex);

    ChildNetworkResult StartLocked(
        const chainregistry::ChainId& chain_id,
        std::optional<ChildNetworkConfig> config)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    ChildNetworkManager(ChainManager& chain_manager,
                        const CChainParams& chain_params,
                        CScheduler& scheduler,
                        uint64_t max_upload_target =
                            DEFAULT_CHILD_UPLOAD_TARGET_BYTES);
    ~ChildNetworkManager() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    ChildNetworkResult Start(const chainregistry::ChainId& chain_id,
                             std::optional<ChildNetworkConfig> config = std::nullopt)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult Stop(const chainregistry::ChainId& chain_id)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult AddNode(const chainregistry::ChainId& chain_id,
                               const std::string& endpoint)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult RemoveNode(const chainregistry::ChainId& chain_id,
                                  const std::string& endpoint)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult SetBindEndpoints(
        const chainregistry::ChainId& chain_id,
        std::vector<std::string> endpoints)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult SetDiscovery(
        const chainregistry::ChainId& chain_id,
        bool enabled,
        std::vector<std::string> bootstrap)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult SetNetworkActive(
        const chainregistry::ChainId& chain_id,
        bool active) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkResult RelayTransaction(
        const chainregistry::ChainId& chain_id,
        const CTransactionRef& transaction)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void StopAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    bool IsRunning(const chainregistry::ChainId& chain_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkInfo GetInfo(
        const chainregistry::ChainId& chain_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildNetworkStats GetStats(
        const chainregistry::ChainId& chain_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::vector<ChildNetworkStats> List() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildBandwidthStats GetBandwidthStats() const;
};

} // namespace node

#endif // BITCOIN_NODE_CHILD_NETWORK_MANAGER_H
