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

    explicit AuthorityFixture(unsigned char first = 1)
    {
        for (unsigned char i{first}; i < first + 5; ++i) {
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

BOOST_AUTO_TEST_CASE(policy_and_handover_encodings)
{
    const AuthorityFixture old_keys;
    const AuthorityFixture new_keys{11};
    const chainregistry::DealerAuthorityTransition transition{154, old_keys.authority, new_keys.authority};
    BOOST_REQUIRE(transition.IsValid());
    BOOST_CHECK(transition.Pending(153));
    BOOST_CHECK(!transition.Pending(154));
    BOOST_CHECK(transition.Effective(153, {}) == old_keys.authority);
    BOOST_CHECK(transition.Effective(154, {}) == new_keys.authority);
    DataStream encoded;
    encoded << transition;
    BOOST_CHECK_EQUAL(encoded.size(), 4U + 2U * (2U + 5U * 32U));
    chainregistry::DealerAuthorityTransition decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded == transition);
    BOOST_CHECK(decoded.GetHash() == transition.GetHash());
    BOOST_CHECK(old_keys.authority.GetHash() != new_keys.authority.GetHash());
    DataStream empty;
    empty << chainregistry::DealerAuthorityTransition{};
    empty >> decoded;
    BOOST_CHECK(decoded == chainregistry::DealerAuthorityTransition{});

    DataStream complete;
    complete << transition;
    for (size_t length{0}; length < complete.size(); ++length) {
        SpanReader truncated{std::span{complete.data(), length}};
        decoded = transition;
        BOOST_CHECK_THROW(truncated >> decoded, std::ios_base::failure);
        BOOST_CHECK(decoded == transition);
    }
    for (unsigned int count : {0U, 6U, 255U}) {
        DataStream invalid;
        invalid << uint8_t{1} << static_cast<uint8_t>(count);
        auto policy{old_keys.authority};
        BOOST_CHECK_THROW(invalid >> policy, std::ios_base::failure);
        BOOST_CHECK(policy == old_keys.authority);
    }
    auto invalid{transition};
    invalid.activation_height = 144;
    BOOST_CHECK(!invalid.IsValid());
    invalid = transition;
    invalid.next.threshold = 3;
    BOOST_CHECK(!invalid.IsValid());
    invalid = transition;
    invalid.next = invalid.previous;
    BOOST_CHECK(!invalid.IsValid());
}

BOOST_AUTO_TEST_CASE(dual_quorum_delayed_rotation_and_undo)
{
    const AuthorityFixture old_keys;
    const AuthorityFixture new_keys{11};
    const uint256 genesis{uint256::ONE};
    constexpr uint32_t inclusion{10}, activation{154};
    chainregistry::RotateAuthority rotation{
        .authority_sequence = 1,
        .previous_policy_hash = old_keys.authority.GetHash(),
        .next_authority = new_keys.authority,
    };
    const auto sign = [&](chainregistry::RotateAuthority& op) {
        const auto digest{*chainregistry::ComputeDealerAuthorityHash(genesis, op)};
        op.authority_signatures = old_keys.Sign(digest, 0x0f);
        op.next_authority_signatures = new_keys.Sign(digest, 0x1e);
    };
    sign(rotation);
    const auto make_tx = [&](const chainregistry::RegistryOperation& op) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        tx.vout.emplace_back(0, chainregistry::BuildOperationScript(op));
        tx.vout.emplace_back(1, CScript{} << OP_1 << old_keys.authority.keys[0]);
        return CTransaction{tx};
    };
    const auto parsed{chainregistry::ParseOperationScript(chainregistry::BuildOperationScript(rotation))};
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(std::get<chainregistry::RotateAuthority>(*parsed.operation) == rotation);
    chainregistry::ChainRegistry registry;
    const auto original_root{registry.ComputeRoot()};
    for (bool old_quorum : {false, true}) {
        auto partial{rotation};
        const auto digest{*chainregistry::ComputeDealerAuthorityHash(genesis, rotation)};
        if (old_quorum) partial.authority_signatures = old_keys.Sign(digest, 0x07);
        else partial.next_authority_signatures = new_keys.Sign(digest, 0x07);
        BOOST_CHECK(registry.ApplyTransaction(make_tx(partial), inclusion, genesis, old_keys.authority).error == chainregistry::RegistryError::INVALID_AUTHORITY_SIGNATURE);
        BOOST_CHECK(registry.ComputeRoot() == original_root);
    }
    BOOST_CHECK(!registry.ApplyTransaction(make_tx(rotation), inclusion, uint256{}, old_keys.authority).IsValid());
    BOOST_CHECK(!registry.ApplyTransaction(make_tx(rotation), 0, genesis, old_keys.authority).IsValid());
    BOOST_CHECK(!registry.ApplyTransaction(make_tx(rotation), UINT32_MAX - 143, genesis, old_keys.authority).IsValid());
    for (int mutation{0}; mutation < 3; ++mutation) {
        auto invalid{rotation};
        if (mutation == 0) invalid.previous_policy_hash = uint256::ONE;
        if (mutation == 1) invalid.next_authority.threshold = 3;
        if (mutation == 2) invalid.next_authority = old_keys.authority;
        sign(invalid);
        BOOST_CHECK(registry.ApplyTransaction(make_tx(invalid), inclusion, genesis, old_keys.authority).error == chainregistry::RegistryError::INVALID_AUTHORITY_ROTATION);
        BOOST_CHECK(registry.ComputeRoot() == original_root);
    }
    const auto applied{registry.ApplyTransaction(make_tx(rotation), inclusion, genesis, old_keys.authority)};
    BOOST_REQUIRE(applied.IsValid());
    BOOST_REQUIRE(applied.undo);
    BOOST_CHECK_EQUAL(registry.AuthoritySequence(), 1U);
    BOOST_CHECK_EQUAL(registry.AuthorityTransition().activation_height, activation);
    const auto rotated_root{registry.ComputeRoot()};
    BOOST_CHECK(rotated_root != original_root);
    auto overlap{rotation};
    overlap.authority_sequence = 2;
    sign(overlap);
    BOOST_CHECK(registry.ApplyTransaction(make_tx(overlap), activation - 1, genesis, old_keys.authority).error == chainregistry::RegistryError::AUTHORITY_ROTATION_PENDING);

    const CScript payout{CScript{} << OP_1 << old_keys.authority.keys[0]};
    chainregistry::AuthorizeDealer authorization{
        .authority_sequence = 2, .authorization_nonce = uint256::ONE,
        .control_key = old_keys.authority.keys[0], .control_output = 1,
        .payout_script = {payout.begin(), payout.end()}, .initial_licenses = 10,
    };
    const auto digest{*chainregistry::ComputeDealerAuthorityHash(genesis, authorization)};
    for (uint32_t height : {inclusion, activation - 1, activation, activation + 1}) {
        const bool before{height < activation};
        BOOST_CHECK(registry.Authority(height, old_keys.authority) == (before ? old_keys.authority : new_keys.authority));
        for (bool use_old : {false, true}) {
            auto candidate{registry};
            authorization.authority_signatures = (use_old ? old_keys : new_keys).Sign(digest, 0x0f);
            const auto result{candidate.ApplyTransaction(make_tx(authorization), height, genesis, old_keys.authority)};
            BOOST_CHECK_EQUAL(result.IsValid(), use_old == before);
            if (result.IsValid()) {
                BOOST_REQUIRE(result.undo);
                BOOST_REQUIRE(candidate.Undo(*result.undo));
                BOOST_CHECK(candidate.ComputeRoot() == rotated_root);
                BOOST_CHECK(candidate.AuthorityTransition() == registry.AuthorityTransition());
            }
        }
    }
    chainregistry::ChainRegistry loaded;
    BOOST_REQUIRE(loaded.LoadState({}, {}, registry.AuthoritySequence(), registry.AuthorityTransition()).IsValid());
    BOOST_CHECK(loaded.ComputeRoot() == rotated_root);
    const auto absent{chainregistry::ChainId::FromUint256(uint256::ONE)};
    auto proof{*registry.GetNonInclusionProof(absent)};
    BOOST_CHECK(chainregistry::VerifyRegistryNonInclusion(absent, proof, rotated_root));
    proof.authority_state_hash = chainregistry::DealerAuthorityTransition{}.GetHash();
    BOOST_CHECK(!chainregistry::VerifyRegistryNonInclusion(absent, proof, rotated_root));
    // A later handover uses the effective on-chain authority, not the genesis
    // keys. Undo must restore the full previous handover and its activation.
    chainregistry::RotateAuthority second{
        .authority_sequence = 2,
        .previous_policy_hash = new_keys.authority.GetHash(),
        .next_authority = old_keys.authority,
    };
    const auto second_digest{*chainregistry::ComputeDealerAuthorityHash(genesis, second)};
    second.authority_signatures = new_keys.Sign(second_digest, 0x0f);
    second.next_authority_signatures = old_keys.Sign(second_digest, 0x0f);
    const auto again{loaded.ApplyTransaction(make_tx(second), activation, genesis, old_keys.authority)};
    BOOST_REQUIRE(again.IsValid());
    BOOST_REQUIRE(again.undo);
    BOOST_CHECK(loaded.Authority(activation + 143, old_keys.authority) == new_keys.authority);
    BOOST_CHECK(loaded.Authority(activation + 144, old_keys.authority) == old_keys.authority);
    BOOST_REQUIRE(loaded.Undo(*again.undo));
    BOOST_CHECK(loaded.ComputeRoot() == rotated_root);
    DataStream undo_stream;
    undo_stream << *applied.undo;
    chainregistry::RegistryUndo undo;
    undo_stream >> undo;
    BOOST_REQUIRE(loaded.Undo(undo));
    BOOST_CHECK(loaded.ComputeRoot() == original_root);
    BOOST_CHECK(loaded.Authority(activation, old_keys.authority) == old_keys.authority);
    BOOST_CHECK(!loaded.Undo(undo));
}

BOOST_AUTO_TEST_SUITE_END()
