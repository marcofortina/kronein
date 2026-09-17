// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <common/args.h>
#include <key_io.h>
#include <logging.h>

namespace wallet {
fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet() / "wallets";
    }

    return path;
}

WalletDescriptor GenerateWalletDescriptor(const CExtPubKey& master_key, const OutputType& addr_type, bool internal)
{
    assert(addr_type == OutputType::BECH32M);
    int64_t creation_time = Now<NodeSeconds>().time_since_epoch().count();

    std::string xpub = EncodeExtPubKey(master_key);

    // Build descriptor string
    std::string desc_prefix = "tr(" + xpub + "/86h";
    const std::string desc_suffix = "/*)";

    // Mainnet derives at 0', testnet and regtest derive at 1'
    if (Params().IsTestChain()) {
        desc_prefix += "/1h";
    } else {
        desc_prefix += "/0h";
    }

    std::string internal_path = internal ? "/1" : "/0";
    std::string desc_str = desc_prefix + "/0h" + internal_path + desc_suffix;

    // Make the descriptor
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
    WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
    return w_desc;
}

} // namespace wallet
