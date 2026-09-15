// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

#include <consensus/params.h>

const std::array<VBDeploymentInfo,Consensus::MAX_VERSION_BITS_DEPLOYMENTS> VersionBitsDeploymentInfo{
    VBDeploymentInfo{
        .name = "testdummy",
        .gbt_optional_rule = true,
    },
    VBDeploymentInfo{
        .name = "taproot",
        .gbt_optional_rule = true,
    },
};
