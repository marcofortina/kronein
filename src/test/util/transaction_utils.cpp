// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <script/signingprovider.h>
#include <test/util/transaction_utils.h>

CMutableTransaction BuildCreditingTransaction(const CScript& scriptPubKey, int nValue)
{
    CMutableTransaction txCredit;
    txCredit.version = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = nValue;

    return txCredit;
}

CMutableTransaction BuildSpendingTransaction(const CScript& scriptSig, const CScriptWitness& scriptWitness, const CTransaction& txCredit)
{
    CMutableTransaction txSpend;
    txSpend.version = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].scriptWitness = scriptWitness;
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

void BulkTransaction(CMutableTransaction& tx, int32_t target_weight)
{
    tx.vout.emplace_back(0, CScript() << OP_RETURN);
    auto unpadded_weight{GetTransactionWeight(CTransaction(tx))};
    assert(target_weight >= unpadded_weight);

    // determine number of needed padding bytes by converting weight difference to vbytes
    auto dummy_vbytes = (target_weight - unpadded_weight + (WITNESS_SCALE_FACTOR - 1)) / WITNESS_SCALE_FACTOR;
    // compensate for the increase of the compact-size encoded script length
    // (note that the length encoding of the unpadded output script needs one byte)
    dummy_vbytes -= GetSizeOfCompactSize(dummy_vbytes) - 1;

    // pad transaction by repeatedly appending a dummy opcode to the output script
    tx.vout[0].scriptPubKey.insert(tx.vout[0].scriptPubKey.end(), dummy_vbytes, OP_1);

    // actual weight should be at most 3 higher than target weight
    assert(GetTransactionWeight(CTransaction(tx)) >= target_weight);
    assert(GetTransactionWeight(CTransaction(tx)) <= target_weight + 3);
}

bool SignSignature(const SigningProvider &provider, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, int nHashType, SignatureData& sig_data)
{
    assert(nIn < txTo.vin.size());

    MutableTransactionSignatureCreator creator(txTo, nIn, nHashType);

    bool ret = ProduceSignature(provider, creator, fromPubKey, sig_data);
    UpdateInput(txTo.vin.at(nIn), sig_data);
    return ret;
}

bool SignSignature(const SigningProvider &provider, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType, SignatureData& sig_data)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(provider, txout.scriptPubKey, txTo, nIn, nHashType, sig_data);
}
