// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/sigcache.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <cstddef>
#include <optional>
#include <vector>

void initialize_script_sigcache()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

FUZZ_TARGET(script_sigcache, .init = initialize_script_sigcache)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const auto max_sigcache_bytes{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, DEFAULT_SIGNATURE_CACHE_BYTES)};
    SignatureCache signature_cache{max_sigcache_bytes};

    const std::optional<CMutableTransaction> mutable_transaction = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
    const CTransaction tx{mutable_transaction ? *mutable_transaction : CMutableTransaction{}};
    const unsigned int n_in = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    const bool store = fuzzed_data_provider.ConsumeBool();
    PrecomputedTransactionData tx_data;
    CachingTransactionSignatureChecker caching_transaction_signature_checker{mutable_transaction ? &tx : nullptr, n_in, store, signature_cache, tx_data};
    const auto random_bytes = fuzzed_data_provider.ConsumeBytes<unsigned char>(64);
    const XOnlyPubKey pub_key(ConsumeUInt256(fuzzed_data_provider));
    if (random_bytes.size() == 64) {
        (void)caching_transaction_signature_checker.VerifySchnorrSignature(random_bytes, pub_key, ConsumeUInt256(fuzzed_data_provider));
    }
}
