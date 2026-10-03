// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/chainregistry.h>
#include <key.h>
#include <primitives/dealerauthority.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <utility>

namespace {

struct AuthorityFixture {
    chainregistry::DealerAuthority authority{.threshold = 4};
    std::vector<CKey> secrets;

    AuthorityFixture()
    {
        for (unsigned char i{1}; i <= 5; ++i) {
            std::array<unsigned char, 32> bytes{};
            bytes.back() = i;
            CKey key;
            key.Set(bytes.begin(), bytes.end(), true);
            secrets.push_back(std::move(key));
        }
        const auto public_key = [](const CKey& secret) {
            const XOnlyPubKey pubkey{secret.GetPubKey()};
            chainregistry::DealerAuthorityKey result;
            std::copy(pubkey.begin(), pubkey.end(), result.begin());
            return result;
        };
        std::ranges::sort(secrets, [&](const auto& a, const auto& b) { return public_key(a) < public_key(b); });
        for (const auto& key : secrets) authority.keys.push_back(public_key(key));
    }

    chainregistry::DealerAuthoritySignatures Sign(const uint256& digest, uint8_t bitmap) const
    {
        chainregistry::DealerAuthoritySignatures result{.signers = bitmap};
        for (size_t i{0}; i < secrets.size(); ++i) {
            if (bitmap & (1U << i)) {
                BOOST_REQUIRE(secrets[i].SignSchnorr(digest, result.signatures.emplace_back(), nullptr, uint256{}));
            }
        }
        return result;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(dealerauthority_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(all_quorums_and_subsets)
{
    AuthorityFixture fixture;
    const uint256 digest{uint256::ONE};
    for (size_t count{1}; count <= 5; ++count) {
        auto authority{fixture.authority};
        authority.keys.resize(count);
        for (uint8_t threshold{1}; threshold <= count; ++threshold) {
            authority.threshold = threshold;
            BOOST_REQUIRE(authority.IsValid());
            for (uint8_t bitmap{0}; bitmap < 32; ++bitmap) {
                const auto bundle{fixture.Sign(digest, bitmap)};
                const bool in_range{bitmap < (1U << count)};
                BOOST_CHECK_EQUAL(bundle.Verify(digest, authority, false), in_range);
                BOOST_CHECK_EQUAL(bundle.Verify(digest, authority), in_range && std::popcount(bitmap) >= threshold);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(invalid_authorities)
{
    AuthorityFixture fixture;
    auto policy{fixture.authority};
    policy.threshold = 0;
    BOOST_CHECK(!policy.IsValid());
    policy.threshold = 6;
    BOOST_CHECK(!policy.IsValid());
    policy = fixture.authority;
    policy.keys.push_back(policy.keys.back());
    BOOST_CHECK(!policy.IsValid());
    policy = fixture.authority;
    policy.keys[1] = policy.keys[0];
    BOOST_CHECK(!policy.IsValid());
    policy = fixture.authority;
    std::swap(policy.keys[0], policy.keys[1]);
    BOOST_CHECK(!policy.IsValid());
    policy = fixture.authority;
    policy.keys[0].fill(0xff);
    BOOST_CHECK(!policy.IsValid());
    BOOST_CHECK(!chainregistry::DealerAuthority{}.IsValid());
}

BOOST_AUTO_TEST_CASE(canonical_bounded_serialization)
{
    AuthorityFixture fixture;
    for (uint8_t bitmap{0}; bitmap < 32; ++bitmap) {
        const auto bundle{fixture.Sign(uint256::ONE, bitmap)};
        DataStream stream;
        stream << bundle;
        BOOST_CHECK_EQUAL(stream.size(), 1 + 64 * std::popcount(bitmap));
        chainregistry::DealerAuthoritySignatures decoded;
        stream >> decoded;
        BOOST_CHECK(stream.empty());
        BOOST_CHECK(decoded == bundle);
    }
    for (unsigned int bitmap{32}; bitmap <= 255; ++bitmap) {
        DataStream stream;
        stream << static_cast<uint8_t>(bitmap);
        chainregistry::DealerAuthoritySignatures decoded;
        BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
        BOOST_CHECK_EQUAL(decoded.signers, 0);
        BOOST_CHECK(decoded.signatures.empty());
    }
    const auto signed_bundle{fixture.Sign(uint256::ONE, 0x1f)};
    DataStream full;
    full << signed_bundle;
    // Every truncation, including a complete bitmap but missing signatures, fails.
    for (size_t length{0}; length < full.size(); ++length) {
        SpanReader stream{std::span{full.data(), length}};
        auto decoded{signed_bundle};
        BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
        BOOST_CHECK(decoded == signed_bundle);
    }
    auto malformed{signed_bundle};
    malformed.signatures.pop_back();
    DataStream stream;
    BOOST_CHECK_THROW(stream << malformed, std::ios_base::failure);
    BOOST_CHECK(stream.empty());
    BOOST_CHECK(!malformed.Verify(uint256::ONE, fixture.authority));
}

BOOST_AUTO_TEST_CASE(duplicates_tampering_and_extra_signatures)
{
    AuthorityFixture fixture;
    const auto bundle{fixture.Sign(uint256::ONE, 0x1f)};
    BOOST_REQUIRE(bundle.Verify(uint256::ONE, fixture.authority));
    BOOST_CHECK(!bundle.Verify(uint256{}, fixture.authority));
    auto modified{bundle};
    modified.signatures[1] = modified.signatures[0];
    BOOST_CHECK(!modified.Verify(uint256::ONE, fixture.authority));
    modified = bundle;
    std::swap(modified.signatures[0], modified.signatures[1]);
    BOOST_CHECK(!modified.Verify(uint256::ONE, fixture.authority));
    modified = bundle;
    // Four valid signatures do not excuse an invalid fifth signature.
    modified.signatures.back()[0] ^= 1;
    BOOST_CHECK(!modified.Verify(uint256::ONE, fixture.authority));
    modified = bundle;
    modified.signers |= 0x20;
    BOOST_CHECK(!modified.Verify(uint256::ONE, fixture.authority));
}

BOOST_AUTO_TEST_CASE(registry_quorum_license_limits_and_replay)
{
    AuthorityFixture fixture;
    const uint256 genesis{uint256::ONE};
    const CScript payout{CScript{} << OP_1 << fixture.authority.keys[0]};
    chainregistry::AuthorizeDealer operation{
        .authority_sequence = 1,
        .authorization_nonce = uint256::ONE,
        .control_key = fixture.authority.keys[0],
        .control_output = 1,
        .payout_script = {payout.begin(), payout.end()},
        .initial_licenses = 10,
    };
    const auto make_tx = [&](const chainregistry::RegistryOperation& payload) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(0, chainregistry::BuildOperationScript(payload));
        tx.vout.emplace_back(1, payout);
        return CTransaction{tx};
    };
    const auto digest{chainregistry::ComputeDealerAuthorityHash(genesis, operation)};
    BOOST_REQUIRE(digest);
    chainregistry::ChainRegistry registry;
    const auto empty_root{registry.ComputeRoot()};
    operation.authority_signatures = fixture.Sign(*digest, 0x07);
    BOOST_CHECK(registry.ApplyTransaction(make_tx(operation), 1, genesis, fixture.authority).error == chainregistry::RegistryError::INVALID_AUTHORITY_SIGNATURE);
    BOOST_CHECK(registry.ComputeRoot() == empty_root);
    operation.authority_signatures = fixture.Sign(*digest, 0x0f);
    BOOST_CHECK(registry.ApplyTransaction(make_tx(operation), 1, uint256{}, fixture.authority).error == chainregistry::RegistryError::INVALID_AUTHORITY_SIGNATURE);
    for (uint32_t count : {0U, 1U, 9U, 11U, 0xffffffffU}) {
        auto invalid{operation};
        invalid.initial_licenses = count;
        BOOST_CHECK(chainregistry::ValidateOperation(invalid) == chainregistry::OperationValidationError::INVALID_LICENSE_COUNT);
        BOOST_CHECK(!registry.ApplyTransaction(make_tx(invalid), 1, genesis, fixture.authority).IsValid());
    }
    const auto authorized{registry.ApplyTransaction(make_tx(operation), 1, genesis, fixture.authority)};
    BOOST_REQUIRE(authorized.IsValid());
    BOOST_REQUIRE(authorized.dealer_id);
    BOOST_REQUIRE(authorized.undo);
    BOOST_CHECK_EQUAL(registry.FindDealer(*authorized.dealer_id)->remaining_licenses, 10U);
    const auto authorized_root{registry.ComputeRoot()};
    BOOST_CHECK(registry.ApplyTransaction(make_tx(operation), 2, genesis, fixture.authority).error == chainregistry::RegistryError::INVALID_AUTHORITY_SEQUENCE);

    chainregistry::UpdateDealer update{.authority_sequence = 2, .dealer_id = *authorized.dealer_id, .added_licenses = 11, .payout_script = {}};
    update.authority_signatures = fixture.Sign(*chainregistry::ComputeDealerAuthorityHash(genesis, update), 0x0f);
    BOOST_CHECK(!registry.ApplyTransaction(make_tx(update), 2, genesis, fixture.authority).IsValid());
    BOOST_CHECK(registry.ComputeRoot() == authorized_root);
    update.added_licenses = 10;
    update.authority_signatures = fixture.Sign(*chainregistry::ComputeDealerAuthorityHash(genesis, update), 0x1e);
    const auto updated{registry.ApplyTransaction(make_tx(update), 2, genesis, fixture.authority)};
    BOOST_REQUIRE(updated.IsValid());
    BOOST_REQUIRE(updated.undo);
    BOOST_CHECK_EQUAL(registry.FindDealer(*authorized.dealer_id)->remaining_licenses, 20U);
    BOOST_REQUIRE(registry.Undo(*updated.undo));
    BOOST_CHECK(registry.ComputeRoot() == authorized_root);
    BOOST_REQUIRE(registry.Undo(*authorized.undo));
    BOOST_CHECK(registry.ComputeRoot() == empty_root);

    // Old single-signature envelopes cannot be reinterpreted as the new format.
    auto script{chainregistry::BuildOperationScript(operation)};
    CScript::const_iterator cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    BOOST_REQUIRE(script.GetOp(cursor, opcode));
    BOOST_REQUIRE(script.GetOp(cursor, opcode, data));
    data[4] = chainregistry::REGISTRY_ENVELOPE_VERSION;
    BOOST_CHECK(chainregistry::ParseOperationScript(CScript{} << OP_RETURN << data).error == chainregistry::OperationParseError::UNSUPPORTED_ENVELOPE_VERSION);
}

BOOST_AUTO_TEST_SUITE_END()
