// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_network_manager.h>

#include <addrdb.h>
#include <addrman.h>
#include <banman.h>
#include <chainparams.h>
#include <chainregistry/child_net.h>
#include <net.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/chain_manager.h>
#include <node/child_net_events.h>
#include <random.h>
#include <scheduler.h>
#include <util/fs_helpers.h>
#include <util/translation.h>

#include <algorithm>
#include <utility>

namespace node {
namespace {

ChildNetworkResult NetworkError(ChildNetworkError error,
                                std::string detail = {})
{
    ChildNetworkResult result;
    result.error = error;
    result.detail = std::move(detail);
    return result;
}

bool IsExplicitEndpoint(const std::string& endpoint)
{
    std::string host;
    uint16_t port{0};
    return SplitHostPort(endpoint, port, host) &&
           !host.empty() && port != 0;
}

ChildNetworkResult ValidateEndpoints(
    const std::vector<std::string>& endpoints)
{
    if (endpoints.size() > MAX_CHILD_CONNECT_NODES) {
        return NetworkError(ChildNetworkError::TOO_MANY_ENDPOINTS);
    }
    std::vector<std::string> unique;
    unique.reserve(endpoints.size());
    for (const std::string& endpoint : endpoints) {
        if (!IsExplicitEndpoint(endpoint)) {
            return NetworkError(ChildNetworkError::INVALID_ENDPOINT, endpoint);
        }
        if (std::find(unique.begin(), unique.end(), endpoint) != unique.end()) {
            return NetworkError(ChildNetworkError::NODE_ALREADY_ADDED, endpoint);
        }
        unique.push_back(endpoint);
    }
    return {};
}

} // namespace

struct ChildNetworkManager::Network {
    chainregistry::ChainId chain_id;
    fs::path network_path;
    MessageStartChars message_start;
    std::unique_ptr<NetGroupManager> netgroup;
    std::unique_ptr<AddrMan> addrman;
    BanMan banman;
    CConnman connman;
    std::unique_ptr<ChildNetEvents> events;
    bool started{false};

    Network(const chainregistry::ChainId& id,
            fs::path path,
            MessageStartChars magic,
            std::unique_ptr<NetGroupManager> groups,
            std::unique_ptr<AddrMan> addresses,
            const CChainParams& params,
            ChainManager& manager,
            const chainregistry::ReferenceChildDefinition& definition)
        : chain_id{id},
          network_path{std::move(path)},
          message_start{magic},
          netgroup{std::move(groups)},
          addrman{std::move(addresses)},
          banman{network_path / "banlist",
                 /*client_interface=*/nullptr,
                 DEFAULT_MISBEHAVING_BANTIME},
          connman{FastRandomContext{}.rand64(),
                  FastRandomContext{}.rand64(),
                  *addrman,
                  *netgroup,
                  params},
          events{std::make_unique<ChildNetEvents>(
              connman, manager, definition)}
    {
    }

    ~Network()
    {
        if (started) {
            connman.Interrupt();
            connman.Stop();
        }
    }

    ChildNetworkStats Stats() const
    {
        ChildNetworkStats result{
            .chain_id = chain_id,
            .running = started,
            .network_active = connman.GetNetworkActive(),
            .connections = connman.GetNodeCount(ConnectionDirection::Both),
            .handshaken = events->HandshakenPeerCount(),
            .added_nodes = {},
        };
        for (const AddedNodeInfo& node :
             connman.GetAddedNodeInfo(/*include_connected=*/true)) {
            result.added_nodes.push_back(node.m_params.m_added_node);
        }
        return result;
    }
};

ChildNetworkManager::ChildNetworkManager(
    ChainManager& chain_manager,
    const CChainParams& chain_params,
    CScheduler& scheduler)
    : m_chain_manager{chain_manager},
      m_chain_params{chain_params},
      m_scheduler{scheduler}
{
}

ChildNetworkManager::~ChildNetworkManager()
{
    StopAll();
}

ChildNetworkResult ChildNetworkManager::Start(
    const chainregistry::ChainId& chain_id,
    const ChildNetworkConfig& config)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    if (const auto endpoints{ValidateEndpoints(config.connect)};
        !endpoints.IsValid()) {
        return endpoints;
    }
    const auto definition{m_chain_manager.Definition(chain_id)};
    if (!definition) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
    }

    LOCK(m_mutex);
    if (m_networks.contains(chain_id)) {
        return NetworkError(ChildNetworkError::ALREADY_RUNNING);
    }

    const fs::path network_path{
        m_chain_manager.DataPath(chain_id) / "network"};
    try {
        TryCreateDirectories(network_path);
    } catch (const fs::filesystem_error&) {
        return NetworkError(
            ChildNetworkError::DATA_DIRECTORY_ERROR,
            fs::PathToString(network_path));
    }
    const MessageStartChars message_start{
        chainregistry::DeriveChildMessageStart(chain_id)};
    auto netgroup{std::make_unique<NetGroupManager>(
        NetGroupManager::NoAsmap())};
    auto loaded_addrman{LoadAddrman(
        *netgroup,
        network_path / "peers.dat",
        message_start)};
    if (!loaded_addrman) {
        return NetworkError(
            ChildNetworkError::PEER_STORE_ERROR,
            util::ErrorString(loaded_addrman).original);
    }

    auto network{std::make_unique<Network>(
        chain_id,
        network_path,
        message_start,
        std::move(netgroup),
        std::move(*loaded_addrman),
        m_chain_params,
        m_chain_manager,
        *definition)};
    CConnman::Options options;
    options.m_local_services = NODE_NONE;
    options.m_max_automatic_connections = 0;
    options.m_msgproc = network->events.get();
    options.m_banman = &network->banman;
    options.nSendBufferMaxSize = DEFAULT_MAXSENDBUFFER * 1000;
    options.nReceiveFloodSize = DEFAULT_MAXRECEIVEBUFFER * 1000;
    for (const auto& endpoint : config.connect) {
        options.m_added_nodes.push_back(endpoint);
    }
    options.bind_on_any = false;
    options.m_use_addrman_outgoing = false;
    options.m_listen = false;
    options.m_dns_seed = false;
    options.m_fixed_seeds = false;
    options.m_private_broadcast = false;
    options.m_schedule_maintenance = false;
    options.m_persist_addrman = true;
    options.m_interrupt_socks5 = false;
    options.m_addrman_path = network_path / "peers.dat";
    options.m_anchors_path = network_path / "anchors.dat";
    options.m_addrman_message_start = message_start;
    network->connman.SetNetworkActive(config.network_active);
    network->started = true;
    if (!network->connman.Start(m_scheduler, options)) {
        return NetworkError(ChildNetworkError::START_FAILED);
    }
    m_networks.emplace(chain_id, std::move(network));
    return {};
}

ChildNetworkResult ChildNetworkManager::Stop(
    const chainregistry::ChainId& chain_id)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    std::unique_ptr<Network> network;
    {
        LOCK(m_mutex);
        const auto entry{m_networks.find(chain_id)};
        if (entry == m_networks.end()) {
            return NetworkError(ChildNetworkError::NOT_RUNNING);
        }
        network = std::move(entry->second);
        m_networks.erase(entry);
    }
    network->connman.Interrupt();
    network->connman.Stop();
    network->started = false;
    return {};
}

ChildNetworkResult ChildNetworkManager::AddNode(
    const chainregistry::ChainId& chain_id,
    const std::string& endpoint)
{
    if (!IsExplicitEndpoint(endpoint)) {
        return NetworkError(ChildNetworkError::INVALID_ENDPOINT, endpoint);
    }
    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    if (entry->second->connman.GetAddedNodeInfo(true).size() >=
        MAX_CHILD_CONNECT_NODES) {
        return NetworkError(ChildNetworkError::TOO_MANY_ENDPOINTS);
    }
    if (!entry->second->connman.AddNode({endpoint})) {
        return NetworkError(ChildNetworkError::NODE_ALREADY_ADDED, endpoint);
    }
    return {};
}

ChildNetworkResult ChildNetworkManager::RemoveNode(
    const chainregistry::ChainId& chain_id,
    const std::string& endpoint)
{
    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    if (!entry->second->connman.RemoveAddedNode(endpoint)) {
        return NetworkError(ChildNetworkError::NODE_NOT_ADDED, endpoint);
    }
    entry->second->connman.DisconnectNode(endpoint);
    return {};
}

void ChildNetworkManager::Interrupt()
{
    LOCK(m_mutex);
    for (const auto& [_, network] : m_networks) {
        network->connman.Interrupt();
    }
}

void ChildNetworkManager::StopAll()
{
    std::map<chainregistry::ChainId, std::unique_ptr<Network>> networks;
    {
        LOCK(m_mutex);
        networks.swap(m_networks);
    }
    for (const auto& [_, network] : networks) {
        network->connman.Interrupt();
    }
    for (const auto& [_, network] : networks) {
        network->connman.Stop();
        network->started = false;
    }
}

bool ChildNetworkManager::IsRunning(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    return !chain_id.IsNull() && m_networks.contains(chain_id);
}

ChildNetworkStats ChildNetworkManager::GetStats(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        ChildNetworkStats result;
        result.chain_id = chain_id;
        return result;
    }
    return entry->second->Stats();
}

std::vector<ChildNetworkStats> ChildNetworkManager::List() const
{
    LOCK(m_mutex);
    std::vector<ChildNetworkStats> result;
    result.reserve(m_networks.size());
    for (const auto& [_, network] : m_networks) {
        result.push_back(network->Stats());
    }
    return result;
}

} // namespace node
