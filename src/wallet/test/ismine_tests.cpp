// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(ismine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ismine_taproot)
{
    const CKey key{GenerateRandomKey()};
    const CPubKey pubkey{key.GetPubKey()};
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());

    auto spk_manager{CreateDescriptor(wallet, "tr(" + EncodeSecret(key) + ")", true)};

    TaprootBuilder builder;
    builder.Finalize(XOnlyPubKey{pubkey});
    BOOST_CHECK(spk_manager->IsMine(GetScriptForDestination(builder.GetOutput())));

    const CKey other_key{GenerateRandomKey()};
    TaprootBuilder other_builder;
    other_builder.Finalize(XOnlyPubKey{other_key.GetPubKey()});
    BOOST_CHECK(!spk_manager->IsMine(GetScriptForDestination(other_builder.GetOutput())));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
