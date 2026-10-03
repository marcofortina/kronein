// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_network_manager.h>

#include <addrdb.h>
#include <addrman.h>
#include <banman.h>
#include <chainparams.h>
#include <chainregistry/child_net.h>
#include <common/settings.h>
#include <net.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/chain_manager.h>
#include <node/child_net_events.h>
#include <random.h>
#include <scheduler.h>
#include <util/check.h>
#include <util/fs_helpers.h>
#include <util/time.h>
#include <util/translation.h>
#include <univalue.h>

#include <algorithm>
#include <utility>

namespace node {
namespace {

constexpr uint32_t CHILD_NETWORK_CONFIG_VERSION{3};
constexpr const char* CHILD_NETWORK_CONFIG_FILENAME{"config.json"};

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

struct ParsedBindEndpoints {
    ChildNetworkResult result;
    std::vector<CService> services;
};

struct ParsedBootstrapEndpoints {
    ChildNetworkResult result;
    std::vector<CService> services;
};

ParsedBootstrapEndpoints ParseBootstrapEndpoints(
    const std::vector<std::string>& endpoints)
{
    ParsedBootstrapEndpoints parsed;
    if (endpoints.size() > MAX_CHILD_BOOTSTRAP_NODES) {
        parsed.result = NetworkError(
            ChildNetworkError::TOO_MANY_BOOTSTRAP_ENDPOINTS);
        return parsed;
    }
    parsed.services.reserve(endpoints.size());
    for (const std::string& endpoint : endpoints) {
        if (!IsExplicitEndpoint(endpoint)) {
            parsed.result = NetworkError(
                ChildNetworkError::INVALID_BOOTSTRAP_ENDPOINT, endpoint);
            return parsed;
        }
        const auto service{Lookup(
            endpoint,
            /*portDefault=*/0,
            /*fAllowLookup=*/false)};
        if (!service || service->GetPort() == 0 ||
            std::find(parsed.services.begin(), parsed.services.end(), *service) !=
                parsed.services.end()) {
            parsed.result = NetworkError(
                ChildNetworkError::INVALID_BOOTSTRAP_ENDPOINT, endpoint);
            return parsed;
        }
        parsed.services.push_back(*service);
    }
    return parsed;
}

ParsedBindEndpoints ParseBindEndpoints(
    const std::vector<std::string>& endpoints)
{
    ParsedBindEndpoints parsed;
    if (endpoints.size() > MAX_CHILD_BIND_ENDPOINTS) {
        parsed.result = NetworkError(
            ChildNetworkError::TOO_MANY_BIND_ENDPOINTS);
        return parsed;
    }
    parsed.services.reserve(endpoints.size());
    for (const std::string& endpoint : endpoints) {
        if (!IsExplicitEndpoint(endpoint)) {
            parsed.result = NetworkError(
                ChildNetworkError::INVALID_BIND_ENDPOINT, endpoint);
            return parsed;
        }
        const auto service{Lookup(
            endpoint,
            /*portDefault=*/0,
            /*fAllowLookup=*/false)};
        if (!service || service->GetPort() == 0 ||
            std::find(parsed.services.begin(), parsed.services.end(), *service) !=
                parsed.services.end()) {
            parsed.result = NetworkError(
                ChildNetworkError::INVALID_BIND_ENDPOINT, endpoint);
            return parsed;
        }
        parsed.services.push_back(*service);
    }
    return parsed;
}

struct LoadedNetworkConfig {
    ChildNetworkResult result;
    ChildNetworkConfig config;
};

LoadedNetworkConfig ReadNetworkConfig(const fs::path& path)
{
    LoadedNetworkConfig loaded;
    if (!fs::exists(path)) return loaded;

    std::map<std::string, common::SettingsValue> values;
    std::vector<std::string> errors;
    if (!common::ReadSettings(path, values, errors)) {
        loaded.result = NetworkError(
            ChildNetworkError::CONFIG_READ_ERROR,
            errors.empty() ? fs::PathToString(path) : errors.front());
        return loaded;
    }
    const auto version{values.find("version")};
    const auto network_active{values.find("network_active")};
    const auto connect{values.find("connect")};
    const auto bind{values.find("bind")};
    const auto discovery{values.find("discovery")};
    const auto bootstrap{values.find("bootstrap")};
    if (version == values.end() || network_active == values.end() ||
        connect == values.end() || !version->second.isNum() ||
        !network_active->second.isBool() || !connect->second.isArray()) {
        loaded.result = NetworkError(
            ChildNetworkError::CONFIG_INVALID,
            fs::PathToString(path));
        return loaded;
    }
    const int64_t config_version{version->second.getInt<int64_t>()};
    const bool version_1{config_version == 1 && values.size() == 3 &&
                         bind == values.end()};
    const bool version_2{
        config_version == 2 && values.size() == 4 &&
        bind != values.end() && bind->second.isArray()};
    const bool version_3{
        config_version == CHILD_NETWORK_CONFIG_VERSION && values.size() == 6 &&
        bind != values.end() && bind->second.isArray() &&
        discovery != values.end() && discovery->second.isBool() &&
        bootstrap != values.end() && bootstrap->second.isArray()};
    if (!version_1 && !version_2 && !version_3) {
        loaded.result = NetworkError(
            ChildNetworkError::CONFIG_INVALID,
            fs::PathToString(path));
        return loaded;
    }
    loaded.config.network_active = network_active->second.get_bool();
    for (const UniValue& endpoint : connect->second.getValues()) {
        if (!endpoint.isStr()) {
            loaded.result = NetworkError(
                ChildNetworkError::CONFIG_INVALID,
                fs::PathToString(path));
            return loaded;
        }
        loaded.config.connect.push_back(endpoint.get_str());
    }
    if (version_2 || version_3) {
        for (const UniValue& endpoint : bind->second.getValues()) {
            if (!endpoint.isStr()) {
                loaded.result = NetworkError(
                    ChildNetworkError::CONFIG_INVALID,
                    fs::PathToString(path));
                return loaded;
            }
            loaded.config.bind.push_back(endpoint.get_str());
        }
    }
    if (version_3) {
        loaded.config.discovery = discovery->second.get_bool();
        for (const UniValue& endpoint : bootstrap->second.getValues()) {
            if (!endpoint.isStr()) {
                loaded.result = NetworkError(
                    ChildNetworkError::CONFIG_INVALID,
                    fs::PathToString(path));
                return loaded;
            }
            loaded.config.bootstrap.push_back(endpoint.get_str());
        }
    }
    loaded.result = ValidateEndpoints(loaded.config.connect);
    if (!loaded.result.IsValid()) {
        loaded.result.error = ChildNetworkError::CONFIG_INVALID;
        loaded.result.detail = fs::PathToString(path);
        return loaded;
    }
    const auto parsed_binds{ParseBindEndpoints(loaded.config.bind)};
    if (!parsed_binds.result.IsValid()) {
        loaded.result = NetworkError(
            ChildNetworkError::CONFIG_INVALID,
            fs::PathToString(path));
        return loaded;
    }
    const auto parsed_bootstrap{
        ParseBootstrapEndpoints(loaded.config.bootstrap)};
    if (!parsed_bootstrap.result.IsValid()) {
        loaded.result = NetworkError(
            ChildNetworkError::CONFIG_INVALID,
            fs::PathToString(path));
    }
    return loaded;
}

ChildNetworkResult WriteNetworkConfig(
    const fs::path& path,
    const ChildNetworkConfig& config)
{
    UniValue connect{UniValue::VARR};
    for (const std::string& endpoint : config.connect) {
        connect.push_back(endpoint);
    }
    UniValue bind{UniValue::VARR};
    for (const std::string& endpoint : config.bind) {
        bind.push_back(endpoint);
    }
    UniValue bootstrap{UniValue::VARR};
    for (const std::string& endpoint : config.bootstrap) {
        bootstrap.push_back(endpoint);
    }
    fs::path temporary{path};
    temporary += ".tmp";
    std::vector<std::string> errors;
    const std::map<std::string, common::SettingsValue> values{
        {"version", static_cast<int64_t>(CHILD_NETWORK_CONFIG_VERSION)},
        {"network_active", config.network_active},
        {"connect", std::move(connect)},
        {"bind", std::move(bind)},
        {"bootstrap", std::move(bootstrap)},
        {"discovery", config.discovery},
    };
    if (!common::WriteSettings(temporary, values, errors) ||
        !RenameOver(temporary, path)) {
        return NetworkError(
            ChildNetworkError::CONFIG_WRITE_ERROR,
            errors.empty() ? fs::PathToString(path) : errors.front());
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
    ChildNetworkConfig config;
    bool started{false};

    Network(const chainregistry::ChainId& id,
            fs::path path,
            MessageStartChars magic,
            std::unique_ptr<NetGroupManager> groups,
            std::unique_ptr<AddrMan> addresses,
            const CChainParams& params,
            ChainManager& manager,
            ChildBandwidthLimiter& bandwidth,
            const chainregistry::ReferenceChildDefinition& definition,
            ChildNetworkConfig network_config)
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
              connman,
              *addrman,
              manager,
              bandwidth,
              definition,
              network_config.discovery)},
          config{std::move(network_config)}
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
            .inbound_netgroup_rejections =
                events->InboundNetgroupRejections(),
            .known_addresses = events->KnownAddressCount(),
            .rate_limited_requests = events->RateLimitedRequests(),
            .discovery = config.discovery,
            .added_nodes = {},
            .bind_endpoints = {},
            .bootstrap_nodes = {},
        };
        result.added_nodes = config.connect;
        result.bind_endpoints = config.bind;
        result.bootstrap_nodes = config.bootstrap;
        return result;
    }
};

ChildNetworkManager::ChildNetworkManager(
    ChainManager& chain_manager,
    const CChainParams& chain_params,
    CScheduler& scheduler,
    uint64_t max_upload_target)
    : m_chain_manager{chain_manager},
      m_chain_params{chain_params},
      m_scheduler{scheduler},
      m_bandwidth{max_upload_target}
{
}

ChildNetworkManager::~ChildNetworkManager()
{
    StopAll();
}

ChildNetworkResult ChildNetworkManager::Start(
    const chainregistry::ChainId& chain_id,
    std::optional<ChildNetworkConfig> config)
{
    LOCK(m_mutex);
    return StartLocked(chain_id, std::move(config));
}

ChildNetworkResult ChildNetworkManager::StartLocked(
    const chainregistry::ChainId& chain_id,
    std::optional<ChildNetworkConfig> config)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    const auto definition{m_chain_manager.Definition(chain_id)};
    if (!definition) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
    }

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
    const fs::path config_path{
        network_path / fs::PathFromString(CHILD_NETWORK_CONFIG_FILENAME)};
    ChildNetworkConfig effective_config;
    if (config) {
        effective_config = std::move(*config);
    } else {
        const auto loaded_config{ReadNetworkConfig(config_path)};
        if (!loaded_config.result.IsValid()) return loaded_config.result;
        effective_config = loaded_config.config;
    }
    if (const auto endpoints{ValidateEndpoints(effective_config.connect)};
        !endpoints.IsValid()) {
        return endpoints;
    }
    auto parsed_binds{ParseBindEndpoints(effective_config.bind)};
    if (!parsed_binds.result.IsValid()) return parsed_binds.result;
    auto parsed_bootstrap{
        ParseBootstrapEndpoints(effective_config.bootstrap)};
    if (!parsed_bootstrap.result.IsValid()) return parsed_bootstrap.result;
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
    if (!parsed_bootstrap.services.empty()) {
        std::vector<CAddress> addresses;
        addresses.reserve(parsed_bootstrap.services.size());
        const NodeSeconds now{Now<NodeSeconds>()};
        for (const CService& service : parsed_bootstrap.services) {
            addresses.emplace_back(service, NODE_NETWORK, now);
        }
        CNetAddr source;
        source.SetInternal("child-bootstrap");
        (*loaded_addrman)->Add(addresses, source);
    }

    auto network{std::make_unique<Network>(
        chain_id,
        network_path,
        message_start,
        std::move(netgroup),
        std::move(*loaded_addrman),
        m_chain_params,
        m_chain_manager,
        m_bandwidth,
        *definition,
        effective_config)};
    CConnman::Options options;
    options.m_local_services = NODE_NONE;
    options.m_max_automatic_connections = effective_config.discovery
        ? MAX_CHILD_AUTOMATIC_CONNECTIONS
        : 0;
    options.m_max_inbound = effective_config.bind.empty()
        ? 0
        : MAX_CHILD_INBOUND_CONNECTIONS;
    options.m_msgproc = network->events.get();
    options.m_banman = &network->banman;
    options.nSendBufferMaxSize = DEFAULT_MAXSENDBUFFER * 1000;
    options.nReceiveFloodSize = DEFAULT_MAXRECEIVEBUFFER * 1000;
    for (const auto& endpoint : effective_config.connect) {
        options.m_added_nodes.push_back(endpoint);
    }
    options.vBinds = std::move(parsed_binds.services);
    options.m_advertise_binds = false;
    options.bind_on_any = false;
    options.m_use_addrman_outgoing = effective_config.discovery;
    options.m_listen = !effective_config.bind.empty();
    options.m_dns_seed = false;
    options.m_fixed_seeds = false;
    options.m_private_broadcast = false;
    options.m_schedule_maintenance = false;
    options.m_persist_addrman = true;
    options.m_interrupt_socks5 = false;
    options.m_addrman_path = network_path / "peers.dat";
    options.m_anchors_path = network_path / "anchors.dat";
    options.m_addrman_message_start = message_start;
    network->connman.SetNetworkActive(effective_config.network_active);
    network->started = true;
    if (!network->connman.Start(m_scheduler, options)) {
        return NetworkError(ChildNetworkError::START_FAILED);
    }
    if (const auto saved{WriteNetworkConfig(config_path, effective_config)};
        !saved.IsValid()) {
        return saved;
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

ChildNetworkResult ChildNetworkManager::RelayTransaction(
    const chainregistry::ChainId& chain_id,
    const CTransactionRef& transaction)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    if (!transaction) {
        return NetworkError(ChildNetworkError::NULL_TRANSACTION);
    }
    LOCK(m_mutex);
    const auto network{m_networks.find(chain_id)};
    if (network == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    ChildNetworkResult result;
    result.relayed_peers =
        network->second->events->RelayTransaction(transaction);
    return result;
}

ChildNetworkResult ChildNetworkManager::AddNode(
    const chainregistry::ChainId& chain_id,
    const std::string& endpoint)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    if (!IsExplicitEndpoint(endpoint)) {
        return NetworkError(ChildNetworkError::INVALID_ENDPOINT, endpoint);
    }
    if (!m_chain_manager.Definition(chain_id)) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
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
    entry->second->config.connect.push_back(endpoint);
    auto saved{WriteNetworkConfig(
        entry->second->network_path /
            fs::PathFromString(CHILD_NETWORK_CONFIG_FILENAME),
        entry->second->config)};
    if (!saved.IsValid()) {
        entry->second->config.connect.pop_back();
        entry->second->connman.RemoveAddedNode(endpoint);
        return saved;
    }
    return {};
}

ChildNetworkResult ChildNetworkManager::RemoveNode(
    const chainregistry::ChainId& chain_id,
    const std::string& endpoint)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    if (!m_chain_manager.Definition(chain_id)) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
    }
    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    if (!entry->second->connman.RemoveAddedNode(endpoint)) {
        return NetworkError(ChildNetworkError::NODE_NOT_ADDED, endpoint);
    }
    const auto configured{std::find(
        entry->second->config.connect.begin(),
        entry->second->config.connect.end(),
        endpoint)};
    Assume(configured != entry->second->config.connect.end());
    entry->second->config.connect.erase(configured);
    auto saved{WriteNetworkConfig(
        entry->second->network_path /
            fs::PathFromString(CHILD_NETWORK_CONFIG_FILENAME),
        entry->second->config)};
    if (!saved.IsValid()) {
        entry->second->config.connect.push_back(endpoint);
        entry->second->connman.AddNode({endpoint});
        return saved;
    }
    entry->second->connman.DisconnectNode(endpoint);
    return {};
}

ChildNetworkResult ChildNetworkManager::SetNetworkActive(
    const chainregistry::ChainId& chain_id,
    bool active)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    if (!m_chain_manager.Definition(chain_id)) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
    }
    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    ChildNetworkConfig previous_config{entry->second->config};
    if (previous_config.network_active == active) return {};

    ChildNetworkConfig updated_config{previous_config};
    updated_config.network_active = active;
    if (active) {
        std::unique_ptr<Network> previous_network{std::move(entry->second)};
        m_networks.erase(entry);
        previous_network->connman.Interrupt();
        previous_network->connman.Stop();
        previous_network->started = false;

        auto updated{StartLocked(
            chain_id, std::move(updated_config))};
        if (updated.IsValid()) return {};

        const auto restored{StartLocked(
            chain_id, std::move(previous_config))};
        if (!restored.IsValid()) {
            return NetworkError(
                ChildNetworkError::START_FAILED,
                "failed to restore the inactive child network");
        }
        return updated;
    }

    auto saved{WriteNetworkConfig(
        entry->second->network_path /
            fs::PathFromString(CHILD_NETWORK_CONFIG_FILENAME),
        updated_config)};
    if (!saved.IsValid()) return saved;
    entry->second->config = std::move(updated_config);
    entry->second->connman.SetNetworkActive(false);
    return {};
}

ChildNetworkResult ChildNetworkManager::SetBindEndpoints(
    const chainregistry::ChainId& chain_id,
    std::vector<std::string> endpoints)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    const auto parsed{ParseBindEndpoints(endpoints)};
    if (!parsed.result.IsValid()) return parsed.result;
    if (!m_chain_manager.Definition(chain_id)) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
    }

    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    ChildNetworkConfig previous_config{entry->second->config};
    if (previous_config.bind == endpoints) return {};

    std::unique_ptr<Network> previous_network{std::move(entry->second)};
    m_networks.erase(entry);
    previous_network->connman.Interrupt();
    previous_network->connman.Stop();
    previous_network->started = false;

    ChildNetworkConfig updated_config{previous_config};
    updated_config.bind = std::move(endpoints);
    auto updated{StartLocked(chain_id, std::move(updated_config))};
    if (updated.IsValid()) return {};

    const auto restored{StartLocked(chain_id, std::move(previous_config))};
    if (!restored.IsValid()) {
        return NetworkError(
            ChildNetworkError::START_FAILED,
            "failed to restore the previous child network configuration");
    }
    return updated;
}

ChildNetworkResult ChildNetworkManager::SetDiscovery(
    const chainregistry::ChainId& chain_id,
    bool enabled,
    std::vector<std::string> bootstrap)
{
    if (chain_id.IsNull()) {
        return NetworkError(ChildNetworkError::NULL_CHAIN_ID);
    }
    const auto parsed{ParseBootstrapEndpoints(bootstrap)};
    if (!parsed.result.IsValid()) return parsed.result;
    if (!m_chain_manager.Definition(chain_id)) {
        return NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
    }
    if (!m_chain_manager.IsLoaded(chain_id)) {
        return NetworkError(ChildNetworkError::CHAIN_NOT_LOADED);
    }

    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry == m_networks.end()) {
        return NetworkError(ChildNetworkError::NOT_RUNNING);
    }
    ChildNetworkConfig previous_config{entry->second->config};
    if (previous_config.discovery == enabled &&
        previous_config.bootstrap == bootstrap) {
        return {};
    }

    std::unique_ptr<Network> previous_network{std::move(entry->second)};
    m_networks.erase(entry);
    previous_network->connman.Interrupt();
    previous_network->connman.Stop();
    previous_network->started = false;

    ChildNetworkConfig updated_config{previous_config};
    updated_config.discovery = enabled;
    updated_config.bootstrap = std::move(bootstrap);
    auto updated{StartLocked(chain_id, std::move(updated_config))};
    if (updated.IsValid()) return {};

    const auto restored{StartLocked(chain_id, std::move(previous_config))};
    if (!restored.IsValid()) {
        return NetworkError(
            ChildNetworkError::START_FAILED,
            "failed to restore the previous child network configuration");
    }
    return updated;
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
    return GetInfo(chain_id).stats;
}

ChildNetworkInfo ChildNetworkManager::GetInfo(
    const chainregistry::ChainId& chain_id) const
{
    ChildNetworkInfo info;
    info.stats.chain_id = chain_id;
    if (chain_id.IsNull()) {
        info.result = NetworkError(ChildNetworkError::NULL_CHAIN_ID);
        return info;
    }
    if (!m_chain_manager.Definition(chain_id)) {
        info.result = NetworkError(ChildNetworkError::UNKNOWN_CHAIN);
        return info;
    }
    const fs::path config_path{
        m_chain_manager.DataPath(chain_id) / "network" /
        fs::PathFromString(CHILD_NETWORK_CONFIG_FILENAME)};

    LOCK(m_mutex);
    const auto entry{m_networks.find(chain_id)};
    if (entry != m_networks.end()) {
        info.stats = entry->second->Stats();
        return info;
    }
    const auto loaded_config{ReadNetworkConfig(config_path)};
    if (!loaded_config.result.IsValid()) {
        info.result = loaded_config.result;
        return info;
    }
    info.stats.network_active = loaded_config.config.network_active;
    info.stats.added_nodes = loaded_config.config.connect;
    info.stats.bind_endpoints = loaded_config.config.bind;
    info.stats.discovery = loaded_config.config.discovery;
    info.stats.bootstrap_nodes = loaded_config.config.bootstrap;
    return info;
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

ChildBandwidthStats ChildNetworkManager::GetBandwidthStats() const
{
    return m_bandwidth.GetStats(
        std::chrono::duration_cast<std::chrono::seconds>(
            MockableSteadyClock::now().time_since_epoch()));
}

} // namespace node
