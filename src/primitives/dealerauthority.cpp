// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/dealerauthority.h>

#include <pubkey.h>

namespace chainregistry {

bool DealerAuthority::IsValid() const
{
    if (keys.empty() || keys.size() > MAX_DEALER_AUTHORITY_KEYS ||
        threshold == 0 || threshold > keys.size()) return false;
    for (size_t i{0}; i < keys.size(); ++i) {
        if (!XOnlyPubKey{keys[i]}.IsFullyValid()) return false;
        if (i > 0 && !(keys[i - 1] < keys[i])) return false;
    }
    return true;
}

bool DealerAuthoritySignatures::Verify(const uint256& digest, const DealerAuthority& authority, bool require_quorum) const
{
    if (!authority.IsValid() || !IsWellFormed() || signers >= (1U << authority.keys.size())) return false;
    if (require_quorum && signatures.size() < authority.threshold) return false;
    size_t signature_index{0};
    for (size_t key_index{0}; key_index < authority.keys.size(); ++key_index) {
        if (!(signers & (1U << key_index))) continue;
        if (!XOnlyPubKey{authority.keys[key_index]}.VerifySchnorr(digest, signatures[signature_index++])) return false;
    }
    return true;
}

} // namespace chainregistry
