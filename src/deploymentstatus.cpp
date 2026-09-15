// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentstatus.h>

#include <consensus/params.h>
#include <versionbits.h>

#include <type_traits>

/* Basic sanity checking for DeploymentPos and ValidDeployment. */

static_assert(ValidDeployment(Consensus::DEPLOYMENT_TESTDUMMY), "sanity check of DeploymentPos failed (TESTDUMMY not valid)");
static_assert(!ValidDeployment(Consensus::MAX_VERSION_BITS_DEPLOYMENTS), "sanity check of DeploymentPos failed (MAX value considered valid)");
/* ValidDeployment only checks the upper bound. Check that the lowest possible
 * value of the type is also a valid deployment.
 */

template<typename T, T x>
static constexpr bool is_minimum()
{
    using U = std::underlying_type_t<T>;
    return x == std::numeric_limits<U>::min();
}

static_assert(is_minimum<Consensus::DeploymentPos, Consensus::DEPLOYMENT_TESTDUMMY>(), "testdummy is not minimum value for DeploymentPos");
