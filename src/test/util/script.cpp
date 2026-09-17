// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <test/util/script.h>
#include <util/string.h>

#include <stdexcept>

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
