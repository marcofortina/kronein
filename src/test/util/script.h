// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SCRIPT_H
#define BITCOIN_TEST_UTIL_SCRIPT_H

#include <script/script.h>
#include <script/verify_flags.h>

#include <string>

static const CScript P2TR_DUMMY{CScript{} << OP_1 << std::vector<unsigned char>(32)};
static const std::vector<uint8_t> TAPROOT_OP_TRUE_LEAF{uint8_t{OP_TRUE}};
static const std::vector<uint8_t> TAPROOT_OP_TRUE_OUTPUT_KEY{
    0x29, 0x13, 0xb2, 0x52, 0xfe, 0x53, 0x78, 0x30,
    0xf8, 0x43, 0xbf, 0xdc, 0x5f, 0xa7, 0xd2, 0x0b,
    0xa4, 0x86, 0x39, 0xa8, 0x7c, 0x86, 0xff, 0x83,
    0x7b, 0x92, 0xd0, 0x83, 0xc5, 0x5a, 0xd7, 0xc1,
};
static const CScript P2TR_OP_TRUE{CScript{} << OP_1 << TAPROOT_OP_TRUE_OUTPUT_KEY};
static const std::vector<uint8_t> TAPROOT_OP_TRUE_CONTROL_BLOCK{
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01,
};
static const std::vector<std::vector<uint8_t>> P2TR_OP_TRUE_WITNESS_STACK{
    TAPROOT_OP_TRUE_LEAF,
    TAPROOT_OP_TRUE_CONTROL_BLOCK,
};

script_verify_flags ParseScriptFlags(std::string flags);

#endif // BITCOIN_TEST_UTIL_SCRIPT_H
