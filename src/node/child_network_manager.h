// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_NETWORK_MANAGER_H
#define KRONEIN_NODE_CHILD_NETWORK_MANAGER_H

#include <primitives/chainregistry.h>
#include <sync.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

class CChainParams;
class CScheduler;

namespace node {

class ChainManager;

inline constexpr size_t MAX_CHILD_CONNECT_NODES{8};

struct ChildNetworkConfig {
    std::vector<std::string> connect;
    bool network_active{true};
};

enum class ChildNetworkError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    ALREADY_RUNNING,
    NOT_RUNNING,
    TOO_MANY_ENDPOINTS,
    INVALID_ENDPOINT,
    DATA_DIRECTORY_ERROR,
    PEER_STORE_ERROR,
    START_FAILED,
    NODE_ALREADY_ADDED,
    NODE_NOT_ADDED,
};

struct ChildNetworkResult {
    ChildNetworkError error{ChildNetworkError::NONE};
    std::string detail;

    bool IsValid() const { return error == ChildNetworkError::NONE; }
};

struct ChildNetworkStats {
    chainregistry::ChainId chain_id;
    bool running{false};
    bool network_active{false};
    size_t connections{0};
    size_t handshaken{0};
    std::vector<std::string> added_nodes;
};

/** Owns one physically separate CConnman stack for every loaded child. */
class ChildNetworkManager
{
private:
    struct Network;

    ChainManager& m_chain_manager;
    const CChainParams& m_chain_params;
    CScheduler& m_scheduler;
    mutable Mutex m_mutex;
    std::map<chainregistry::ChainId, std::unique_ptr<Network>> m_networks
        GUARDED_BY(m_mutex);

public:
    ChildNetworkManager(ChainManager& chain_manager,
                        const CChainParams& chain_params,
                        CScheduler& scheduler);
    ~ChildNetworkManager();

    ChildNetworkResult Start(const chainregistry::ChainId& chain_id,
                             const ChildNetworkConfig& config = {});
    ChildNetworkResult Stop(const chainregistry::ChainId& chain_id);
    ChildNetworkResult AddNode(const chainregistry::ChainId& chain_id,
                               const std::string& endpoint);
    ChildNetworkResult RemoveNode(const chainregistry::ChainId& chain_id,
                                  const std::string& endpoint);
    void Interrupt();
    void StopAll();

    bool IsRunning(const chainregistry::ChainId& chain_id) const;
    ChildNetworkStats GetStats(
        const chainregistry::ChainId& chain_id) const;
    std::vector<ChildNetworkStats> List() const;
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_NETWORK_MANAGER_H
