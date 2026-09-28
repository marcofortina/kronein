// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_NETWORK_MANAGER_H
#define KRONEIN_NODE_CHILD_NETWORK_MANAGER_H

#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <chrono>
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
inline constexpr std::chrono::seconds CHILD_UPLOAD_TIMEFRAME{
    std::chrono::hours{24}};

struct ChildBandwidthStats {
    uint64_t target{0};
    uint64_t bytes_sent{0};
    uint64_t bytes_left{0};
    std::chrono::seconds timeframe{0};
    std::chrono::seconds time_left{0};
    bool target_reached{false};
};

/** Process-wide block-serving budget shared by every child network. */
class ChildBandwidthLimiter
{
private:
    const uint64_t m_target;
    mutable Mutex m_mutex;
    mutable bool m_cycle_started GUARDED_BY(m_mutex){false};
    mutable std::chrono::seconds m_cycle_start GUARDED_BY(m_mutex){0};
    mutable uint64_t m_bytes_sent GUARDED_BY(m_mutex){0};

    void RefreshCycle(std::chrono::seconds now) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    explicit ChildBandwidthLimiter(uint64_t target) : m_target{target} {}

    bool TryReserve(uint64_t bytes, std::chrono::seconds now);
    ChildBandwidthStats GetStats(std::chrono::seconds now) const;
};

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
    ~ChildNetworkManager();

    ChildNetworkResult Start(const chainregistry::ChainId& chain_id,
                             std::optional<ChildNetworkConfig> config = std::nullopt);
    ChildNetworkResult Stop(const chainregistry::ChainId& chain_id);
    ChildNetworkResult AddNode(const chainregistry::ChainId& chain_id,
                               const std::string& endpoint);
    ChildNetworkResult RemoveNode(const chainregistry::ChainId& chain_id,
                                  const std::string& endpoint);
    ChildNetworkResult SetBindEndpoints(
        const chainregistry::ChainId& chain_id,
        std::vector<std::string> endpoints);
    ChildNetworkResult SetDiscovery(
        const chainregistry::ChainId& chain_id,
        bool enabled,
        std::vector<std::string> bootstrap);
    ChildNetworkResult SetNetworkActive(
        const chainregistry::ChainId& chain_id,
        bool active);
    ChildNetworkResult RelayTransaction(
        const chainregistry::ChainId& chain_id,
        const CTransactionRef& transaction);
    void Interrupt();
    void StopAll();

    bool IsRunning(const chainregistry::ChainId& chain_id) const;
    ChildNetworkInfo GetInfo(
        const chainregistry::ChainId& chain_id) const;
    ChildNetworkStats GetStats(
        const chainregistry::ChainId& chain_id) const;
    std::vector<ChildNetworkStats> List() const;
    ChildBandwidthStats GetBandwidthStats() const;
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_NETWORK_MANAGER_H
