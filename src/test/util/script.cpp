// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <test/util/script.h>
#include <util/string.h>

#include <stdexcept>

bool IsValidFlagCombination(script_verify_flags flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

script_verify_flags ParseScriptFlags(std::string flag_string)
{
    script_verify_flags flags{SCRIPT_VERIFY_NONE};
    if (flag_string.empty() || flag_string == "NONE") return flags;

    const auto& names{ScriptFlagNamesToEnum()};
    for (const std::string& word : util::SplitString(flag_string, ',')) {
        const auto it{names.find(word)};
        if (it == names.end()) throw std::runtime_error("Unknown script verification flag: " + word);
        flags |= it->second;
    }
    return flags;
}
