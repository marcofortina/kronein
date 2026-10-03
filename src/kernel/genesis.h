// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_KERNEL_GENESIS_H
#define BITCOIN_KERNEL_GENESIS_H

#include <consensus/amount.h>

#include <cstdint>
#include <string_view>

class CBlock;
class CScript;

/** Shared network/tool constructor. Timestamp bytes may contain NULs. */
CBlock CreateGenesisBlock(std::string_view timestamp, const CScript& genesis_output_script,
                          uint32_t time, uint32_t nonce, uint32_t bits, int32_t version,
                          const CAmount& reward);

#endif // BITCOIN_KERNEL_GENESIS_H
