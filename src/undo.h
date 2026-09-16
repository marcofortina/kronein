// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <serialize.h>

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) { READWRITE(obj.vprevout); }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    SERIALIZE_METHODS(CBlockUndo, obj) { READWRITE(obj.vtxundo); }
};

#endif // BITCOIN_UNDO_H
