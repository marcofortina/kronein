// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/randomx.h>

#include <crypto/randomx/upstream/src/randomx.h>

#include <algorithm>
#include <limits>
#include <list>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace randomx_pow {
namespace {

randomx_flags RecommendedFlags()
{
    randomx_flags flags{randomx_get_flags() | RANDOMX_FLAG_V2};
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    // JIT-generated writes cannot update MemorySanitizer's shadow memory.
    // Keep compiler-instrumented AES and Argon2 intrinsics enabled; only the
    // generated code must be replaced by the interpreter.
    flags = static_cast<randomx_flags>(flags & ~(RANDOMX_FLAG_JIT | RANDOMX_FLAG_SECURE));
#endif
#endif
    if ((flags & RANDOMX_FLAG_JIT) != 0) flags |= RANDOMX_FLAG_SECURE;
    return flags;
}

randomx_flags PortableFlags(Mode mode)
{
    return static_cast<randomx_flags>(RANDOMX_FLAG_V2 | (mode == Mode::FULL ? RANDOMX_FLAG_FULL_MEM : RANDOMX_FLAG_DEFAULT));
}

struct CacheDeleter {
    void operator()(randomx_cache* cache) const
    {
        if (cache != nullptr) randomx_release_cache(cache);
    }
};

struct DatasetDeleter {
    void operator()(randomx_dataset* dataset) const
    {
        if (dataset != nullptr) randomx_release_dataset(dataset);
    }
};

struct VmDeleter {
    void operator()(randomx_vm* vm) const
    {
        if (vm != nullptr) randomx_destroy_vm(vm);
    }
};

using CachePtr = std::unique_ptr<randomx_cache, CacheDeleter>;
using DatasetPtr = std::unique_ptr<randomx_dataset, DatasetDeleter>;
using VmPtr = std::unique_ptr<randomx_vm, VmDeleter>;

void InitializeDataset(randomx_dataset* dataset, randomx_cache* cache, unsigned int requested_threads)
{
    const unsigned long item_count{randomx_dataset_item_count()};
    unsigned int thread_count{requested_threads == 0 ? std::thread::hardware_concurrency() : requested_threads};
    thread_count = std::max(1U, thread_count);
    thread_count = static_cast<unsigned int>(std::min<unsigned long>(thread_count, item_count));

    // RandomX's optimized dataset initializer works on groups of four items.
    // Give every worker except the last an aligned, non-overlapping range.
    unsigned long chunk{(item_count + thread_count - 1) / thread_count};
    chunk = (chunk + 3UL) & ~3UL;

    std::vector<std::thread> workers;
    workers.reserve(thread_count);
    for (unsigned int worker = 0; worker < thread_count; ++worker) {
        const unsigned long start{worker * chunk};
        if (start >= item_count) break;
        const unsigned long count{std::min(chunk, item_count - start)};
        workers.emplace_back([=] { randomx_init_dataset(dataset, cache, start, count); });
    }
    for (auto& worker : workers) worker.join();
}

struct CachedEntry {
    std::vector<unsigned char> key;
    std::shared_ptr<Hasher> hasher;
};

class HasherCache
{
private:
    std::mutex m_light_mutex;
    std::mutex m_full_mutex;
    std::list<CachedEntry> m_light;
    std::list<CachedEntry> m_full;

public:
    std::shared_ptr<Hasher> Get(std::span<const unsigned char> key, Mode mode, unsigned int dataset_threads)
    {
        // Building a full dataset is deliberately isolated from the light
        // cache so local mining cannot stall consensus verification.
        std::lock_guard lock{mode == Mode::LIGHT ? m_light_mutex : m_full_mutex};
        auto& entries{mode == Mode::LIGHT ? m_light : m_full};
        const auto found{std::find_if(entries.begin(), entries.end(), [&](const auto& entry) {
            return std::ranges::equal(entry.key, key);
        })};
        if (found != entries.end()) {
            entries.splice(entries.begin(), entries, found);
            return entries.front().hasher;
        }

        auto hasher{Hasher::Create(key, mode, dataset_threads)};
        if (!hasher) return {};
        entries.push_front({std::vector<unsigned char>{key.begin(), key.end()}, hasher});
        const size_t capacity{mode == Mode::LIGHT ? 2U : 1U};
        while (entries.size() > capacity) entries.pop_back();
        return hasher;
    }
};

HasherCache& GlobalCache()
{
    static HasherCache cache;
    return cache;
}

} // namespace

struct Hasher::Impl {
    Mode mode;
    CachePtr cache;
    DatasetPtr dataset;
    VmPtr vm;
    std::mutex mutex;
};

Hasher::Hasher(std::unique_ptr<Impl> impl) : m_impl{std::move(impl)} {}
Hasher::~Hasher() = default;
Hasher::Hasher(Hasher&&) noexcept = default;
Hasher& Hasher::operator=(Hasher&&) noexcept = default;

std::shared_ptr<Hasher> Hasher::Create(std::span<const unsigned char> key, Mode mode, unsigned int dataset_threads)
{
    if (key.empty()) return {};
    // Keep the full dataset within PTRDIFF_MAX for portable allocations.
    // RandomX v2's dataset exceeds that limit on 32-bit hosts. Reject this
    // mining optimization before building a cache that cannot be used; callers
    // can still use the bit-identical light mode for mining and verification.
    if (mode == Mode::FULL && randomx_dataset_item_count() >
            static_cast<size_t>(std::numeric_limits<std::ptrdiff_t>::max()) / RANDOMX_DATASET_ITEM_SIZE) {
        return {};
    }

    auto impl{std::make_unique<Impl>()};
    impl->mode = mode;

    randomx_flags flags{RecommendedFlags()};
    impl->cache.reset(randomx_alloc_cache(flags));
    if (!impl->cache) {
        flags = RANDOMX_FLAG_V2;
        impl->cache.reset(randomx_alloc_cache(flags));
    }
    if (!impl->cache) return {};
    randomx_init_cache(impl->cache.get(), key.data(), key.size());

    if (mode == Mode::FULL) {
        impl->dataset.reset(randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT));
        if (!impl->dataset) return {};
        InitializeDataset(impl->dataset.get(), impl->cache.get(), dataset_threads);
        flags |= RANDOMX_FLAG_FULL_MEM;
    }

    impl->vm.reset(randomx_create_vm(flags, mode == Mode::LIGHT ? impl->cache.get() : nullptr, impl->dataset.get()));
    if (!impl->vm) {
        const randomx_flags portable{PortableFlags(mode)};
        impl->vm.reset(randomx_create_vm(portable, mode == Mode::LIGHT ? impl->cache.get() : nullptr, impl->dataset.get()));
    }
    if (!impl->vm) return {};
    return std::shared_ptr<Hasher>{new Hasher{std::move(impl)}};
}

std::optional<Hash> Hasher::HashData(std::span<const unsigned char> input)
{
    if (!m_impl || !m_impl->vm || input.empty()) return std::nullopt;
    std::lock_guard lock{m_impl->mutex};
    Hash result;
    randomx_calculate_hash(m_impl->vm.get(), input.data(), input.size(), result.data());
    return result;
}

Mode Hasher::GetMode() const
{
    return m_impl->mode;
}

std::shared_ptr<Hasher> GetCachedHasher(std::span<const unsigned char> key, Mode mode, unsigned int dataset_threads)
{
    return GlobalCache().Get(key, mode, dataset_threads);
}

std::optional<Hash> HashLight(std::span<const unsigned char> key, std::span<const unsigned char> input)
{
    auto hasher{GetCachedHasher(key, Mode::LIGHT)};
    return hasher ? hasher->HashData(input) : std::nullopt;
}

} // namespace randomx_pow
