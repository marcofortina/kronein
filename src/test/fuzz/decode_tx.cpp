// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <primitives/transaction.h>
#include <test/fuzz/fuzz.h>
#include <util/strencodings.h>

#include <string>

FUZZ_TARGET(decode_tx)
{
    const std::string tx_hex = HexStr(buffer);
    CMutableTransaction mtx;
    (void)DecodeHexTx(mtx, tx_hex);
}
