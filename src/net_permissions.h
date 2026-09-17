// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <netbase.h>

#include <string>
#include <type_traits>
#include <vector>

#ifndef BITCOIN_NET_PERMISSIONS_H
#define BITCOIN_NET_PERMISSIONS_H

struct bilingual_str;

extern const std::vector<std::string> NET_PERMISSIONS_DOC;

enum class NetPermissionFlags : uint32_t {
    None = 0,
    // Relay and accept transactions from this peer, even if -blocksonly is true
    // This peer is also not subject to limits on how many transaction INVs are tracked
    Relay = (1U << 3),
    // Always relay transactions from this peer, even if already in mempool
    // Keep parameter interaction: forcerelay implies relay
    ForceRelay = (1U << 2) | Relay,
    // Allow getheaders during IBD and block-download after maxuploadtarget limit
    Download = (1U << 6),
    // Can't be banned/disconnected/discouraged for misbehavior
    NoBan = (1U << 4) | Download,
    // Can request addrs without hitting a privacy-preserving cache, and send us
    // unlimited amounts of addrs.
    Addr = (1U << 7),

    All = ForceRelay | Relay | NoBan | Download | Addr,
};
static inline constexpr NetPermissionFlags operator|(NetPermissionFlags a, NetPermissionFlags b)
{
    using t = std::underlying_type_t<NetPermissionFlags>;
    return static_cast<NetPermissionFlags>(static_cast<t>(a) | static_cast<t>(b));
}

class NetPermissions
{
public:
    NetPermissionFlags m_flags;
    static std::vector<std::string> ToStrings(NetPermissionFlags flags);
    static inline bool HasFlag(NetPermissionFlags flags, NetPermissionFlags f)
    {
        using t = std::underlying_type_t<NetPermissionFlags>;
        return (static_cast<t>(flags) & static_cast<t>(f)) == static_cast<t>(f);
    }
    static inline void AddFlag(NetPermissionFlags& flags, NetPermissionFlags f)
    {
        flags = flags | f;
    }
};

class NetWhitebindPermissions : public NetPermissions
{
public:
    static bool TryParse(const std::string& str, NetWhitebindPermissions& output, bilingual_str& error);
    CService m_service;
};

class NetWhitelistPermissions : public NetPermissions
{
public:
    static bool TryParse(const std::string& str, NetWhitelistPermissions& output, ConnectionDirection& output_connection_direction, bilingual_str& error);
    CSubNet m_subnet;
};

#endif // BITCOIN_NET_PERMISSIONS_H
