// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <consensus/amount.h>
#include <key.h>
#include <musig.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/keyorigin.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/translation.h>
#include <util/vector.h>

typedef std::vector<unsigned char> valtype;

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, checker{&m_txto, nIn, MissingDataBehavior::FAIL},
      m_txdata(nullptr)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const PrecomputedTransactionData* txdata, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type},
      checker{txdata ? MutableTransactionSignatureChecker{&m_txto, nIn, *txdata, MissingDataBehavior::FAIL} :
                       MutableTransactionSignatureChecker{&m_txto, nIn, MissingDataBehavior::FAIL}},
      m_txdata(txdata)
{
}

std::optional<uint256> MutableTransactionSignatureCreator::ComputeSchnorrSignatureHash(const uint256* leaf_hash, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    // BIP341/BIP342 signing needs lots of precomputed transaction data. While some
    // (non-SIGHASH_DEFAULT) sighash modes exist that can work with just some subset
    // of data present, for now, only support signing when everything is provided.
    if (!m_txdata || !m_txdata->m_bip341_taproot_ready || !m_txdata->m_spent_outputs_ready) return std::nullopt;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.
    if (sigversion == SigVersion::TAPSCRIPT) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        if (!leaf_hash) return std::nullopt; // BIP342 signing needs leaf hash.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = *leaf_hash;
    }
    uint256 hash;
    if (!SignatureHashSchnorr(hash, execdata, m_txto, nIn, nHashType, sigversion, *m_txdata, MissingDataBehavior::FAIL)) return std::nullopt;
    return hash;
}

bool MutableTransactionSignatureCreator::CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion) const
{
    CKey key;
    if (!provider.GetKeyByXOnly(pubkey, key)) return false;

    std::optional<uint256> hash = ComputeSchnorrSignatureHash(leaf_hash, sigversion);
    if (!hash.has_value()) return false;

    sig.resize(64);
    // Use uint256{} as aux_rnd for now.
    if (!key.SignSchnorr(*hash, sig, merkle_root, {})) return false;
    if (nHashType) sig.push_back(nHashType);
    return true;
}

std::vector<uint8_t> MutableTransactionSignatureCreator::CreateMuSig2Nonce(const SigningProvider& provider, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion, const SignatureData& sigdata) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    // Retrieve the private key
    CKey key;
    if (!provider.GetKey(part_pubkey.GetID(), key)) return {};

    // Retrieve participant pubkeys
    auto it = sigdata.musig2_pubkeys.find(aggregate_pubkey);
    if (it == sigdata.musig2_pubkeys.end()) return {};
    const std::vector<CPubKey>& pubkeys = it->second;
    if (std::find(pubkeys.begin(), pubkeys.end(), part_pubkey) == pubkeys.end()) return {};

    // Compute sighash
    std::optional<uint256> sighash = ComputeSchnorrSignatureHash(leaf_hash, sigversion);
    if (!sighash.has_value()) return {};

    MuSig2SecNonce secnonce;
    std::vector<uint8_t> out = key.CreateMuSig2Nonce(secnonce, *sighash, aggregate_pubkey, pubkeys);
    if (out.empty()) return {};

    // Store the secnonce in the SigningProvider
    provider.SetMuSig2SecNonce(MuSig2SessionID(script_pubkey, part_pubkey, *sighash), std::move(secnonce));

    return out;
}

bool MutableTransactionSignatureCreator::CreateMuSig2PartialSig(const SigningProvider& provider, uint256& partial_sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    // Retrieve private key
    CKey key;
    if (!provider.GetKey(part_pubkey.GetID(), key)) return false;

    // Retrieve participant pubkeys
    auto it = sigdata.musig2_pubkeys.find(aggregate_pubkey);
    if (it == sigdata.musig2_pubkeys.end()) return false;
    const std::vector<CPubKey>& pubkeys = it->second;
    if (std::find(pubkeys.begin(), pubkeys.end(), part_pubkey) == pubkeys.end()) return {};

    // Retrieve pubnonces
    auto this_leaf_aggkey = std::make_pair(script_pubkey, leaf_hash ? *leaf_hash : uint256());
    auto pubnonce_it = sigdata.musig2_pubnonces.find(this_leaf_aggkey);
    if (pubnonce_it == sigdata.musig2_pubnonces.end()) return false;
    const std::map<CPubKey, std::vector<uint8_t>>& pubnonces = pubnonce_it->second;

    // Check if enough pubnonces
    if (pubnonces.size() != pubkeys.size()) return false;

    // Compute sighash
    std::optional<uint256> sighash = ComputeSchnorrSignatureHash(leaf_hash, sigversion);
    if (!sighash.has_value()) return false;

    // Retrieve the secnonce
    uint256 session_id = MuSig2SessionID(script_pubkey, part_pubkey, *sighash);
    std::optional<std::reference_wrapper<MuSig2SecNonce>> secnonce = provider.GetMuSig2SecNonce(session_id);
    if (!secnonce || !secnonce->get().IsValid()) return false;

    // Compute the sig
    std::optional<uint256> sig = key.CreateMuSig2PartialSig(*sighash, aggregate_pubkey, pubkeys, pubnonces, *secnonce, tweaks);
    if (!sig) return false;
    partial_sig = std::move(*sig);

    // Delete the secnonce now that we're done with it
    assert(!secnonce->get().IsValid());
    provider.DeleteMuSig2Session(session_id);

    return true;
}

bool MutableTransactionSignatureCreator::CreateMuSig2AggregateSig(const std::vector<CPubKey>& participants, std::vector<uint8_t>& sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);
    if (!participants.size()) return false;

    // Retrieve pubnonces and partial sigs
    auto this_leaf_aggkey = std::make_pair(script_pubkey, leaf_hash ? *leaf_hash : uint256());
    auto pubnonce_it = sigdata.musig2_pubnonces.find(this_leaf_aggkey);
    if (pubnonce_it == sigdata.musig2_pubnonces.end()) return false;
    const std::map<CPubKey, std::vector<uint8_t>>& pubnonces = pubnonce_it->second;
    auto partial_sigs_it = sigdata.musig2_partial_sigs.find(this_leaf_aggkey);
    if (partial_sigs_it == sigdata.musig2_partial_sigs.end()) return false;
    const std::map<CPubKey, uint256>& partial_sigs = partial_sigs_it->second;

    // Check if enough pubnonces and partial sigs
    if (pubnonces.size() != participants.size()) return false;
    if (partial_sigs.size() != participants.size()) return false;

    // Compute sighash
    std::optional<uint256> sighash = ComputeSchnorrSignatureHash(leaf_hash, sigversion);
    if (!sighash.has_value()) return false;

    std::optional<std::vector<uint8_t>> res = ::CreateMuSig2AggregateSig(participants, aggregate_pubkey, tweaks, *sighash, pubnonces, partial_sigs);
    if (!res) return false;
    sig = res.value();
    if (nHashType) sig.push_back(nHashType);

    return true;
}

static bool GetPubKey(const SigningProvider& provider, const SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey lists
    const auto& pk_it = sigdata.misc_pubkeys.find(address);
    if (pk_it != sigdata.misc_pubkeys.end()) {
        pubkey = pk_it->second.first;
        return true;
    }
    const auto& tap_pk_it = sigdata.tap_pubkeys.find(address);
    if (tap_pk_it != sigdata.tap_pubkeys.end()) {
        pubkey = tap_pk_it->second.GetEvenCorrespondingCPubKey();
        return true;
    }
    // Query the underlying provider
    return provider.GetPubKey(address, pubkey);
}

static bool SignMuSig2(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const XOnlyPubKey& script_pubkey, const uint256* merkle_root, const uint256* leaf_hash, SigVersion sigversion)
{
    Assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    // Lookup derivation paths for the script pubkey
    KeyOriginInfo agg_info;
    auto misc_pk_it = sigdata.taproot_misc_pubkeys.find(script_pubkey);
    if (misc_pk_it != sigdata.taproot_misc_pubkeys.end()) {
        agg_info = misc_pk_it->second.second;
    }

    for (const auto& [agg_pub, part_pks] : sigdata.musig2_pubkeys) {
        if (part_pks.empty()) continue;

        // Fill participant derivation path info
        for (const auto& part_pk : part_pks) {
            KeyOriginInfo part_info;
            if (provider.GetKeyOrigin(part_pk.GetID(), part_info)) {
                XOnlyPubKey xonly_part(part_pk);
                auto it = sigdata.taproot_misc_pubkeys.find(xonly_part);
                if (it == sigdata.taproot_misc_pubkeys.end()) {
                    it = sigdata.taproot_misc_pubkeys.emplace(xonly_part, std::make_pair(std::set<uint256>(), part_info)).first;
                }
                if (leaf_hash) it->second.first.insert(*leaf_hash);
            }
        }

        // The pubkey in the script may not be the actual aggregate of the participants, but derived from it.
        // Check the derivation, and compute the BIP 32 derivation tweaks
        std::vector<std::pair<uint256, bool>> tweaks;
        CPubKey plain_pub = agg_pub;
        if (XOnlyPubKey(agg_pub) != script_pubkey) {
            if (agg_info.path.empty()) continue;
            // Compute and compare fingerprint
            CKeyID keyid = agg_pub.GetID();
            if (!std::equal(agg_info.fingerprint, agg_info.fingerprint + sizeof(agg_info.fingerprint), keyid.data())) {
                continue;
            }
            // Get the BIP32 derivation tweaks
            CExtPubKey extpub = CreateMuSig2SyntheticXpub(agg_pub);
            for (const int i : agg_info.path) {
                auto& [t, xonly] = tweaks.emplace_back();
                xonly = false;
                if (!extpub.Derive(extpub, i, &t)) {
                    return false;
                }
            }
            Assert(XOnlyPubKey(extpub.pubkey) == script_pubkey);
            plain_pub = extpub.pubkey;
        }

        // Add the merkle root tweak
        if (sigversion == SigVersion::TAPROOT && merkle_root) {
            tweaks.emplace_back(script_pubkey.ComputeTapTweakHash(merkle_root->IsNull() ? nullptr : merkle_root), true);
            std::optional<std::pair<XOnlyPubKey, bool>> tweaked = script_pubkey.CreateTapTweak(merkle_root->IsNull() ? nullptr : merkle_root);
            if (!Assume(tweaked)) return false;
            plain_pub = tweaked->first.GetCPubKeys().at(tweaked->second ? 1 : 0);
        }

        // First try to aggregate
        if (creator.CreateMuSig2AggregateSig(part_pks, sig_out, agg_pub, plain_pub, leaf_hash, tweaks, sigversion, sigdata)) {
            if (sigversion == SigVersion::TAPROOT) {
                sigdata.taproot_key_path_sig = sig_out;
            } else {
                auto lookup_key = std::make_pair(script_pubkey, leaf_hash ? *leaf_hash : uint256());
                sigdata.taproot_script_sigs[lookup_key] = sig_out;
            }
            continue;
        }
        // Cannot aggregate, try making partial sigs for every participant
        auto pub_key_leaf_hash = std::make_pair(plain_pub, leaf_hash ? *leaf_hash : uint256());
        for (const CPubKey& part_pk : part_pks) {
            uint256 partial_sig;
            if (creator.CreateMuSig2PartialSig(provider, partial_sig, agg_pub, plain_pub, part_pk, leaf_hash, tweaks, sigversion, sigdata) && Assume(!partial_sig.IsNull())) {
                sigdata.musig2_partial_sigs[pub_key_leaf_hash].emplace(part_pk, partial_sig);
            }
        }
        // If there are any partial signatures, continue with next aggregate pubkey
        auto partial_sigs_it = sigdata.musig2_partial_sigs.find(pub_key_leaf_hash);
        if (partial_sigs_it != sigdata.musig2_partial_sigs.end() && !partial_sigs_it->second.empty()) {
            continue;
        }
        // No partial sigs, try to make pubnonces
        std::map<CPubKey, std::vector<uint8_t>>& pubnonces = sigdata.musig2_pubnonces[pub_key_leaf_hash];
        for (const CPubKey& part_pk : part_pks) {
            if (pubnonces.contains(part_pk)) continue;
            std::vector<uint8_t> pubnonce = creator.CreateMuSig2Nonce(provider, agg_pub, plain_pub, part_pk, leaf_hash, merkle_root, sigversion, sigdata);
            if (pubnonce.empty()) continue;
            pubnonces[part_pk] = std::move(pubnonce);
        }
    }
    return true;
}

static bool CreateTaprootScriptSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const XOnlyPubKey& pubkey, const uint256& leaf_hash, SigVersion sigversion)
{
    KeyOriginInfo info;
    if (provider.GetKeyOriginByXOnly(pubkey, info)) {
        auto it = sigdata.taproot_misc_pubkeys.find(pubkey);
        if (it == sigdata.taproot_misc_pubkeys.end()) {
            sigdata.taproot_misc_pubkeys.emplace(pubkey, std::make_pair(std::set<uint256>({leaf_hash}), info));
        } else {
            it->second.first.insert(leaf_hash);
        }
    }

    auto lookup_key = std::make_pair(pubkey, leaf_hash);
    auto it = sigdata.taproot_script_sigs.find(lookup_key);
    if (it != sigdata.taproot_script_sigs.end()) {
        sig_out = it->second;
        return true;
    }

    if (creator.CreateSchnorrSig(provider, sig_out, pubkey, &leaf_hash, nullptr, sigversion)) {
        sigdata.taproot_script_sigs[lookup_key] = sig_out;
    } else if (!SignMuSig2(creator, sigdata, provider, sig_out, pubkey, /*merkle_root=*/nullptr, &leaf_hash, sigversion)) {
        return false;
    }

    return sigdata.taproot_script_sigs.contains(lookup_key);
}

template<typename M, typename K, typename V>
miniscript::Availability MsLookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return miniscript::Availability::YES;
    }
    return miniscript::Availability::NO;
}

/**
 * Context for solving a Miniscript.
 * If enough material (access to keys, hash preimages, ..) is given, produces a valid satisfaction.
 */
template<typename Pk>
struct Satisfier {
    using Key = Pk;

    const SigningProvider& m_provider;
    SignatureData& m_sig_data;
    const BaseSignatureCreator& m_creator;

    explicit Satisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                       const BaseSignatureCreator& creator LIFETIMEBOUND) : m_provider(provider),
                                                                           m_sig_data(sig_data),
                                                                           m_creator(creator) {}

    static bool KeyCompare(const Key& a, const Key& b) {
        return a < b;
    }

    //! Get a CPubKey from a key hash. Note the key hash may be of an xonly pubkey.
    template<typename I>
    std::optional<CPubKey> CPubFromPKHBytes(I first, I last) const {
        assert(last - first == 20);
        CPubKey pubkey;
        CKeyID key_id;
        std::copy(first, last, key_id.begin());
        if (GetPubKey(m_provider, m_sig_data, key_id, pubkey)) return pubkey;
        m_sig_data.missing_pubkeys.push_back(key_id);
        return {};
    }

    //! Conversion to raw public key.
    std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    //! Time lock satisfactions.
    bool CheckAfter(uint32_t value) const { return m_creator.Checker().CheckLockTime(CScriptNum(value)); }
    bool CheckOlder(uint32_t value) const { return m_creator.Checker().CheckSequence(CScriptNum(value)); }

    //! Hash preimage satisfactions.
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.sha256_preimages, hash, preimage);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.ripemd160_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash256_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash160_preimages, hash, preimage);
    }

    miniscript::MiniscriptContext MsContext() const {
        return miniscript::MiniscriptContext::TAPSCRIPT;
    }
};

/** Miniscript satisfier specific to Tapscript context. */
struct TapSatisfier: Satisfier<XOnlyPubKey> {
    const uint256& m_leaf_hash;

    explicit TapSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const uint256& leaf_hash LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator),
                            m_leaf_hash(leaf_hash) {}

    //! Conversion from a raw xonly public key.
    template <typename I>
    std::optional<XOnlyPubKey> FromPKBytes(I first, I last) const {
        if (last - first != 32) return {};
        XOnlyPubKey pubkey;
        std::copy(first, last, pubkey.begin());
        return pubkey;
    }

    //! Conversion from a raw xonly public key hash.
    template<typename I>
    std::optional<XOnlyPubKey> FromPKHBytes(I first, I last) const {
        if (auto pubkey = Satisfier::CPubFromPKHBytes(first, last)) return XOnlyPubKey{*pubkey};
        return {};
    }

    //! Satisfy a BIP340 signature check.
    miniscript::Availability Sign(const XOnlyPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateTaprootScriptSig(m_creator, m_sig_data, m_provider, sig, key, m_leaf_hash, SigVersion::TAPSCRIPT)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

static bool SignTaprootScript(const SigningProvider& provider, const BaseSignatureCreator& creator, SignatureData& sigdata, int leaf_version, std::span<const unsigned char> script_bytes, std::vector<valtype>& result)
{
    // Only BIP342 tapscript signing is supported for now.
    if (leaf_version != TAPROOT_LEAF_TAPSCRIPT) return false;

    uint256 leaf_hash = ComputeTapleafHash(leaf_version, script_bytes);
    CScript script = CScript(script_bytes.begin(), script_bytes.end());

    TapSatisfier ms_satisfier{provider, sigdata, creator, leaf_hash};
    const auto ms = miniscript::FromScript(script, ms_satisfier);
    return ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
}

static bool SignTaproot(const SigningProvider& provider, const BaseSignatureCreator& creator, const WitnessV1Taproot& output, SignatureData& sigdata, std::vector<valtype>& result)
{
    TaprootSpendData spenddata;
    TaprootBuilder builder;

    // Gather information about this output.
    if (provider.GetTaprootSpendData(output, spenddata)) {
        sigdata.tr_spenddata.Merge(spenddata);
    }
    if (provider.GetTaprootBuilder(output, builder)) {
        sigdata.tr_builder = builder;
    }
    if (auto agg_keys = provider.GetAllMuSig2ParticipantPubkeys(); !agg_keys.empty()) {
        sigdata.musig2_pubkeys.insert(agg_keys.begin(), agg_keys.end());
    }


    // Try key path spending.
    {
        KeyOriginInfo internal_key_info;
        if (provider.GetKeyOriginByXOnly(sigdata.tr_spenddata.internal_key, internal_key_info)) {
            auto it = sigdata.taproot_misc_pubkeys.find(sigdata.tr_spenddata.internal_key);
            if (it == sigdata.taproot_misc_pubkeys.end()) {
                sigdata.taproot_misc_pubkeys.emplace(sigdata.tr_spenddata.internal_key, std::make_pair(std::set<uint256>(), internal_key_info));
            }
        }

        KeyOriginInfo output_key_info;
        if (provider.GetKeyOriginByXOnly(output, output_key_info)) {
            auto it = sigdata.taproot_misc_pubkeys.find(output);
            if (it == sigdata.taproot_misc_pubkeys.end()) {
                sigdata.taproot_misc_pubkeys.emplace(output, std::make_pair(std::set<uint256>(), output_key_info));
            }
        }

        auto make_keypath_sig = [&](const XOnlyPubKey& pk, const uint256* merkle_root) {
            std::vector<unsigned char> sig;
            if (creator.CreateSchnorrSig(provider, sig, pk, nullptr, merkle_root, SigVersion::TAPROOT)) {
                sigdata.taproot_key_path_sig = sig;
            } else {
                SignMuSig2(creator, sigdata, provider, sig, pk, merkle_root, /*leaf_hash=*/nullptr, SigVersion::TAPROOT);
            }
        };

        // First try signing with internal key
        if (sigdata.taproot_key_path_sig.size() == 0) {
            make_keypath_sig(sigdata.tr_spenddata.internal_key, &sigdata.tr_spenddata.merkle_root);
        }
        // Try signing with output key if still no signature
        if (sigdata.taproot_key_path_sig.size() == 0) {
            make_keypath_sig(output, nullptr);
        }
        if (sigdata.taproot_key_path_sig.size()) {
            result = Vector(sigdata.taproot_key_path_sig);
            return true;
        }
    }

    // Try script path spending.
    std::vector<std::vector<unsigned char>> smallest_result_stack;
    for (const auto& [key, control_blocks] : sigdata.tr_spenddata.scripts) {
        const auto& [script, leaf_ver] = key;
        std::vector<std::vector<unsigned char>> result_stack;
        if (SignTaprootScript(provider, creator, sigdata, leaf_ver, script, result_stack)) {
            result_stack.emplace_back(std::begin(script), std::end(script)); // Push the script
            result_stack.push_back(*control_blocks.begin()); // Push the smallest control block
            if (smallest_result_stack.size() == 0 ||
                GetSerializeSize(result_stack) < GetSerializeSize(smallest_result_stack)) {
                smallest_result_stack = std::move(result_stack);
            }
        }
    }
    if (smallest_result_stack.size() != 0) {
        result = std::move(smallest_result_stack);
        return true;
    }

    return false;
}

bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    if (sigdata.complete) return true;

    std::vector<valtype> solutions;
    const TxoutType which_type{Solver(fromPubKey, solutions)};
    std::vector<valtype> result;
    bool solved{false};

    if (which_type == TxoutType::WITNESS_V1_TAPROOT) {
        sigdata.witness = true;
        solved = SignTaproot(provider, creator, WitnessV1Taproot{XOnlyPubKey{solutions[0]}}, sigdata, result);
        if (solved) {
            sigdata.scriptWitness.stack = std::move(result);
        }
    } else if (which_type == TxoutType::ANCHOR) {
        sigdata.scriptWitness.stack.clear();
        solved = true;
    }

    if (!sigdata.witness) sigdata.scriptWitness.stack.clear();
    sigdata.scriptSig.clear();

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
    return sigdata.complete;
}

SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;

    MutableTransactionSignatureChecker tx_checker(&tx, nIn, MissingDataBehavior::FAIL);
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, &data.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, tx_checker)) {
        data.complete = true;
    }

    return data;
}

void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
    input.scriptWitness = data.scriptWitness;
}

void SignatureData::MergeSignatureData(SignatureData sigdata)
{
    if (complete) return;
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()), std::make_move_iterator(sigdata.signatures.end()));
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker
{
public:
    DummySignatureChecker() = default;
    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror) const override { return sig.size() != 0; }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};
}

const BaseSignatureChecker& DUMMY_CHECKER = DummySignatureChecker();

namespace {
class DummySignatureCreator final : public BaseSignatureCreator {
public:
    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }
    bool CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* tweak, SigVersion sigversion) const override
    {
        sig.assign(64, '\000');
        return true;
    }
    std::vector<uint8_t> CreateMuSig2Nonce(const SigningProvider& provider, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion, const SignatureData& sigdata) const override
    {
        std::vector<uint8_t> out;
        out.assign(MUSIG2_PUBNONCE_SIZE, '\000');
        return out;
    }
    bool CreateMuSig2PartialSig(const SigningProvider& provider, uint256& partial_sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const override
    {
        partial_sig = uint256::ONE;
        return true;
    }
    bool CreateMuSig2AggregateSig(const std::vector<CPubKey>& participants, std::vector<uint8_t>& sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const override
    {
        sig.assign(64, '\000');
        return true;
    }
};

}

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator();

bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors)
{
    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            txdata.Init(txConst, /*spent_outputs=*/{});
            break;
        } else {
            spent_outputs.emplace_back(coin->second.out.nValue, coin->second.out.scriptPubKey);
        }
    }
    if (spent_outputs.size() == mtx.vin.size()) {
        txdata.Init(txConst, std::move(spent_outputs));
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin->second.out.scriptPubKey;
        const CAmount& amount = coin->second.out.nValue;

        SignatureData sigdata = DataFromTransaction(mtx, i, coin->second.out);
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.vout.size())) {
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(mtx, i, &txdata, nHashType), prevPubKey, sigdata);
        }

        UpdateInput(txin, sigdata);

        // amount must be specified for valid segwit signature
        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!sigdata.complete && !VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, txdata, MissingDataBehavior::FAIL), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                input_errors[i] = Untranslated("Signature verification failed with a non-empty signature");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
    }
    return input_errors.empty();
}
