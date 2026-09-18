// Copyright (c) 2024-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>
#include <util/fs.h>

#define BOOST_TEST_MODULE Kronein Kernel Test Suite
#include <boost/test/included/unit_test.hpp>

#include <test/kernel/block_data.h>

#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace btck;

std::string random_string(uint32_t length)
{
    const std::string chars = "0123456789"
                              "abcdefghijklmnopqrstuvwxyz"
                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    static std::random_device rd;
    static std::default_random_engine dre{rd()};
    static std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string random;
    random.reserve(length);
    for (uint32_t i = 0; i < length; i++) {
        random += chars[distribution(dre)];
    }
    return random;
}

std::vector<std::byte> hex_string_to_byte_vec(std::string_view hex)
{
    std::vector<std::byte> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i{0}; i < hex.length(); i += 2) {
        uint8_t byte_value;
        auto [ptr, ec] = std::from_chars(hex.data() + i, hex.data() + i + 2, byte_value, 16);

        if (ec != std::errc{} || ptr != hex.data() + i + 2) {
            throw std::invalid_argument("Invalid hex character");
        }
        bytes.push_back(static_cast<std::byte>(byte_value));
    }
    return bytes;
}

std::string byte_span_to_hex_string_reversed(std::span<const std::byte> bytes)
{
    std::ostringstream oss;

    // Iterate in reverse order
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(static_cast<uint8_t>(*it));
    }

    return oss.str();
}

constexpr std::string_view NATIVE_TX{"01000000013fa9412f35c42bb2b03353db325bb9e7724a1281d40606688ad852a6e86cf0880000000000fdffffff02fc0a102401000000225120eca7e5fc42990da1c2b52cf676e634aa483836ec848f7a70618584b049df1c0c00e1f505000000002251201b9268693c1923fdbffa80c8a91c712aac5a2dc8870daabe89b525b823d56d0d0140438ee2d86f85c29d5f114e248e7dc80f8957c7db6ce29e009db5db169ee338aaac0257c556ee7a74bd20bf80280030cf1f182509974dd14c1c25284d078c54b9cc000000"};
constexpr std::string_view NATIVE_TX_2{"0100000001a480b701887819bc9b8247fef16657921410f65ae484532662a6be52ed4bebec0100000000fdffffff01605af405000000002251201b9268693c1923fdbffa80c8a91c712aac5a2dc8870daabe89b525b823d56d0d014042c3cb45036103a6e9dafb331e5e33e2ace687ec610f1f01bcb93b4d9ef405778112e171d7308ca97bf545a6da48a614dba1891e9d905ede3d107b2610ffeed800000000"};
constexpr std::string_view NATIVE_TWO_INPUT_TX{"010000000201000000000000000000000000000000000000000000000000000000000000000000000000fdffffff02000000000000000000000000000000000000000000000000000000000000000100000000fdffffff0100e1f505000000002251201b9268693c1923fdbffa80c8a91c712aac5a2dc8870daabe89b525b823d56d0d000000000000"};

void check_equal(std::span<const std::byte> _actual, std::span<const std::byte> _expected, bool equal = true)
{
    std::span<const uint8_t> actual{reinterpret_cast<const unsigned char*>(_actual.data()), _actual.size()};
    std::span<const uint8_t> expected{reinterpret_cast<const unsigned char*>(_expected.data()), _expected.size()};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        actual.begin(), actual.end(),
        expected.begin(), expected.end());
}

class TestLog
{
public:
    void LogMessage(std::string_view message)
    {
        std::cout << "kernel: " << message;
    }
};

struct TestDirectory {
    fs::path m_directory;
    TestDirectory(std::string directory_name)
        : m_directory{fs::path{fs::temp_directory_path()} / fs::u8path(directory_name + "_🌽_" + random_string(16))}
    {
        fs::create_directories(m_directory);
    }

    ~TestDirectory()
    {
        fs::remove_all(m_directory);
    }
};

class TestKernelNotifications : public KernelNotifications
{
public:
    void HeaderTipHandler(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        BOOST_CHECK_GT(timestamp, 0);
    }

    void WarningSetHandler(Warning warning, std::string_view message) override
    {
        std::cout << "Kernel warning is set: " << message << std::endl;
    }

    void WarningUnsetHandler(Warning warning) override
    {
        std::cout << "Kernel warning was unset." << std::endl;
    }

    void FlushErrorHandler(std::string_view error) override
    {
        std::cout << error << std::endl;
    }

    void FatalErrorHandler(std::string_view error) override
    {
        std::cout << error << std::endl;
    }
};

class TestValidationInterface : public ValidationInterface
{
public:
    std::optional<std::vector<std::byte>> m_expected_valid_block = std::nullopt;

    void BlockChecked(Block block, BlockValidationStateView state) override
    {
        if (m_expected_valid_block.has_value()) {
            auto ser_block{block.ToBytes()};
            check_equal(m_expected_valid_block.value(), ser_block);
        }

        auto mode{state.GetValidationMode()};
        switch (mode) {
        case ValidationMode::VALID: {
            std::cout << "Valid block" << std::endl;
            return;
        }
        case ValidationMode::INVALID: {
            std::cout << "Invalid block: ";
            auto result{state.GetBlockValidationResult()};
            switch (result) {
            case BlockValidationResult::UNSET:
                std::cout << "initial value. Block has not yet been rejected" << std::endl;
                break;
            case BlockValidationResult::HEADER_LOW_WORK:
                std::cout << "the block header may be on a too-little-work chain" << std::endl;
                break;
            case BlockValidationResult::CONSENSUS:
                std::cout << "invalid by consensus rules (excluding any below reasons)" << std::endl;
                break;
            case BlockValidationResult::CACHED_INVALID:
                std::cout << "this block was cached as being invalid and we didn't store the reason why" << std::endl;
                break;
            case BlockValidationResult::INVALID_HEADER:
                std::cout << "invalid proof of work or time too old" << std::endl;
                break;
            case BlockValidationResult::MUTATED:
                std::cout << "the block's data didn't match the data committed to by the PoW" << std::endl;
                break;
            case BlockValidationResult::MISSING_PREV:
                std::cout << "We don't have the previous block the checked one is built on" << std::endl;
                break;
            case BlockValidationResult::INVALID_PREV:
                std::cout << "A block this one builds on is invalid" << std::endl;
                break;
            case BlockValidationResult::TIME_FUTURE:
                std::cout << "block timestamp was > 2 hours in the future (or our clock is bad)" << std::endl;
                break;
            }
            return;
        }
        case ValidationMode::INTERNAL_ERROR: {
            std::cout << "Internal error" << std::endl;
            return;
        }
        }
    }

    void BlockConnected(Block block, BlockTreeEntry entry) override
    {
        std::cout << "Block connected." << std::endl;
    }

    void PowValidBlock(BlockTreeEntry entry, Block block) override
    {
        std::cout << "Block passed pow verification" << std::endl;
    }

    void BlockDisconnected(Block block, BlockTreeEntry entry) override
    {
        std::cout << "Block disconnected." << std::endl;
    }
};

void run_verify_test(
    const ScriptPubkey& spent_script_pubkey,
    const Transaction& spending_tx,
    const PrecomputedTransactionData* precomputed_txdata,
    unsigned int input_index)
{
    auto status = ScriptVerifyStatus::OK;
    BOOST_CHECK(spent_script_pubkey.Verify(
        spending_tx,
        precomputed_txdata,
        input_index,
        status));
    BOOST_CHECK(status == ScriptVerifyStatus::OK);
}

template <typename T>
concept HasToBytes = requires(T t) { t.ToBytes(); };

template <typename T>
void CheckHandle(T object, T distinct_object)
{
    BOOST_CHECK(object.get() != nullptr);
    BOOST_CHECK(distinct_object.get() != nullptr);
    BOOST_CHECK(object.get() != distinct_object.get());

    if constexpr (HasToBytes<T>) {
        const auto object_bytes = object.ToBytes();
        const auto distinct_bytes = distinct_object.ToBytes();
        BOOST_CHECK(!std::ranges::equal(object_bytes, distinct_bytes));
    }

    // Copy constructor
    T object2(distinct_object);
    BOOST_CHECK_NE(distinct_object.get(), object2.get());
    if constexpr (HasToBytes<T>) {
        check_equal(distinct_object.ToBytes(), object2.ToBytes());
    }

    // Copy assignment
    T object3{distinct_object};
    object2 = object3;
    BOOST_CHECK_NE(object3.get(), object2.get());
    if constexpr (HasToBytes<T>) {
        check_equal(object3.ToBytes(), object2.ToBytes());
    }

    // Move constructor
    auto* original_ptr = object2.get();
    T object4{std::move(object2)};
    BOOST_CHECK_EQUAL(object4.get(), original_ptr);
    BOOST_CHECK_EQUAL(object2.get(), nullptr); // NOLINT(bugprone-use-after-move)
    if constexpr (HasToBytes<T>) {
        check_equal(object4.ToBytes(), object3.ToBytes());
    }

    // Move assignment
    original_ptr = object4.get();
    object2 = std::move(object4);
    BOOST_CHECK_EQUAL(object2.get(), original_ptr);
    BOOST_CHECK_EQUAL(object4.get(), nullptr); // NOLINT(bugprone-use-after-move)
    if constexpr (HasToBytes<T>) {
        check_equal(object2.ToBytes(), object3.ToBytes());
    }
}

template <typename RangeType>
    requires std::ranges::random_access_range<RangeType>
void CheckRange(const RangeType& range, size_t expected_size)
{
    using value_type = std::ranges::range_value_t<RangeType>;

    BOOST_CHECK_EQUAL(range.size(), expected_size);
    BOOST_REQUIRE(range.size() > 0); // Some checks below assume a non-empty range
    BOOST_REQUIRE(!range.empty());

    BOOST_CHECK(range.begin() != range.end());
    BOOST_CHECK_EQUAL(std::distance(range.begin(), range.end()), static_cast<std::ptrdiff_t>(expected_size));
    BOOST_CHECK(range.cbegin() == range.begin());
    BOOST_CHECK(range.cend() == range.end());

    for (size_t i = 0; i < range.size(); ++i) {
        BOOST_CHECK_EQUAL(range[i].get(), (*(range.begin() + i)).get());
    }

    BOOST_CHECK_THROW(range.at(expected_size), std::out_of_range);

    BOOST_CHECK_EQUAL(range.front().get(), range[0].get());
    BOOST_CHECK_EQUAL(range.back().get(), range[expected_size - 1].get());

    auto it = range.begin();
    auto it_copy = it;
    ++it;
    BOOST_CHECK(it != it_copy);
    --it;
    BOOST_CHECK(it == it_copy);
    it = range.begin();
    auto old_it = it++;
    BOOST_CHECK(old_it == range.begin());
    BOOST_CHECK(it == range.begin() + 1);
    old_it = it--;
    BOOST_CHECK(old_it == range.begin() + 1);
    BOOST_CHECK(it == range.begin());

    it = range.begin();
    it += 2;
    BOOST_CHECK(it == range.begin() + 2);
    it -= 2;
    BOOST_CHECK(it == range.begin());

    BOOST_CHECK(range.begin() < range.end());
    BOOST_CHECK(range.begin() <= range.end());
    BOOST_CHECK(range.end() > range.begin());
    BOOST_CHECK(range.end() >= range.begin());
    BOOST_CHECK(range.begin() == range.begin());

    BOOST_CHECK_EQUAL(range.begin()[0].get(), range[0].get());

    size_t count = 0;
    for (auto rit = range.end(); rit != range.begin();) {
        --rit;
        ++count;
    }
    BOOST_CHECK_EQUAL(count, expected_size);

    std::vector<value_type> collected;
    for (const auto& elem : range) {
        collected.push_back(elem);
    }
    BOOST_CHECK_EQUAL(collected.size(), expected_size);

    BOOST_CHECK_EQUAL(std::ranges::size(range), expected_size);

    it = range.begin();
    auto it2 = 1 + it;
    BOOST_CHECK(it2 == it + 1);
}

BOOST_AUTO_TEST_CASE(btck_transaction_tests)
{
    auto tx_data{hex_string_to_byte_vec(NATIVE_TX)};
    auto tx{Transaction{tx_data}};
    auto tx_data_2{hex_string_to_byte_vec(NATIVE_TX_2)};
    auto tx2{Transaction{tx_data_2}};
    CheckHandle(tx, tx2);

    auto invalid_data = hex_string_to_byte_vec("012300");
    BOOST_CHECK_THROW(Transaction{invalid_data}, std::runtime_error);
    auto empty_data = hex_string_to_byte_vec("");
    BOOST_CHECK_THROW(Transaction{empty_data}, std::runtime_error);

    BOOST_CHECK_EQUAL(tx.CountOutputs(), 2);
    BOOST_CHECK_EQUAL(tx.CountInputs(), 1);
    auto broken_tx_data{std::span<std::byte>{tx_data.begin(), tx_data.begin() + 10}};
    BOOST_CHECK_THROW(Transaction{broken_tx_data}, std::runtime_error);
    auto output{tx.GetOutput(tx.CountOutputs() - 1)};
    BOOST_CHECK_EQUAL(output.Amount(), 100000000);
    auto script_pubkey{output.GetScriptPubkey()};
    {
        auto tx_new{Transaction{tx_data}};
        // This is safe, because we now use copy assignment
        TransactionOutput output = tx_new.GetOutput(tx_new.CountOutputs() - 1);
        ScriptPubkey script = output.GetScriptPubkey();

        TransactionOutputView output2 = tx_new.GetOutput(tx_new.CountOutputs() - 1);
        BOOST_CHECK_NE(output.get(), output2.get());
        BOOST_CHECK_EQUAL(output.Amount(), output2.Amount());
        TransactionOutput output3 = output2;
        BOOST_CHECK_NE(output3.get(), output2.get());
        BOOST_CHECK_EQUAL(output3.Amount(), output2.Amount());

        // Non-owned view
        ScriptPubkeyView script2 = output.GetScriptPubkey();
        BOOST_CHECK_NE(script.get(), script2.get());
        check_equal(script.ToBytes(), script2.ToBytes());

        // Non-owned to owned
        ScriptPubkey script3 = script2;
        BOOST_CHECK_NE(script3.get(), script2.get());
        check_equal(script3.ToBytes(), script2.ToBytes());
    }
    BOOST_CHECK_EQUAL(output.Amount(), 100000000);

    auto tx_roundtrip{Transaction{tx.ToBytes()}};
    check_equal(tx_roundtrip.ToBytes(), tx_data);

    // The following code is unsafe, but left here to show limitations of the
    // API, because we preserve the output view beyond the lifetime of the
    // transaction. The view type wrapper should make this clear to the user.
    // auto get_output = [&]() -> TransactionOutputView {
    //     auto tx{Transaction{tx_data}};
    //     return tx.GetOutput(0);
    // };
    // auto output_new = get_output();
    // BOOST_CHECK_EQUAL(output_new.Amount(), 20737411);

    int64_t total_amount{0};
    for (const auto output : tx.Outputs()) {
        total_amount += output.Amount();
    }
    BOOST_CHECK_EQUAL(total_amount, 4999998460);

    auto amount = *(tx.Outputs() | std::ranges::views::filter([](const auto& output) {
                        return output.Amount() == 100000000;
                    }) |
                    std::views::transform([](const auto& output) {
                        return output.Amount();
                    })).begin();
    BOOST_REQUIRE(amount);
    BOOST_CHECK_EQUAL(amount, 100000000);

    CheckRange(tx.Outputs(), tx.CountOutputs());

    ScriptPubkey script_pubkey_roundtrip{script_pubkey.ToBytes()};
    check_equal(script_pubkey_roundtrip.ToBytes(), script_pubkey.ToBytes());
}

BOOST_AUTO_TEST_CASE(btck_script_pubkey)
{
    auto script_data{hex_string_to_byte_vec("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac")};
    std::vector<std::byte> script_data_2 = script_data;
    script_data_2.push_back(std::byte{0x51});
    ScriptPubkey script{script_data};
    ScriptPubkey script2{script_data_2};
    CheckHandle(script, script2);

    std::span<std::byte> empty_data{};
    ScriptPubkey empty_script{empty_data};
    CheckHandle(script, empty_script);
}

BOOST_AUTO_TEST_CASE(btck_transaction_output)
{
    ScriptPubkey script{hex_string_to_byte_vec("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac")};
    TransactionOutput output{script, 1};
    TransactionOutput output2{script, 2};
    CheckHandle(output, output2);
}

BOOST_AUTO_TEST_CASE(btck_transaction_input)
{
    Transaction tx{hex_string_to_byte_vec(NATIVE_TWO_INPUT_TX)};
    TransactionInput input_0 = tx.GetInput(0);
    TransactionInput input_1 = tx.GetInput(1);
    CheckHandle(input_0, input_1);
    CheckRange(tx.Inputs(), tx.CountInputs());
    OutPoint point_0 = input_0.OutPoint();
    OutPoint point_1 = input_1.OutPoint();
    CheckHandle(point_0, point_1);
}

BOOST_AUTO_TEST_CASE(btck_precomputed_txdata) {
    auto tx_data{hex_string_to_byte_vec(NATIVE_TX)};
    auto tx{Transaction{tx_data}};
    auto tx_data_2{hex_string_to_byte_vec(NATIVE_TX_2)};
    auto tx2{Transaction{tx_data_2}};
    auto precomputed_txdata{PrecomputedTransactionData{
        /*tx_to=*/tx,
        /*spent_outputs=*/{},
    }};
    auto precomputed_txdata_2{PrecomputedTransactionData{
        /*tx_to=*/tx2,
        /*spent_outputs=*/{},
    }};
    CheckHandle(precomputed_txdata, precomputed_txdata_2);
}

BOOST_AUTO_TEST_CASE(btck_script_verify_tests)
{
    auto taproot_spent_script_pubkey{ScriptPubkey{hex_string_to_byte_vec("51201b9268693c1923fdbffa80c8a91c712aac5a2dc8870daabe89b525b823d56d0d")}};
    auto taproot_spending_tx{Transaction{hex_string_to_byte_vec(NATIVE_TX_2)}};
    std::vector<TransactionOutput> taproot_spent_outputs;
    taproot_spent_outputs.emplace_back(taproot_spent_script_pubkey, 100000000);
    auto taproot_precomputed_txdata{PrecomputedTransactionData{
        /*tx_to=*/taproot_spending_tx,
        /*spent_outputs=*/taproot_spent_outputs,
    }};
    run_verify_test(
        /*spent_script_pubkey=*/taproot_spent_script_pubkey,
        /*spending_tx=*/taproot_spending_tx,
        /*precomputed_txdata=*/&taproot_precomputed_txdata,
        /*input_index=*/0);
}

BOOST_AUTO_TEST_CASE(logging_tests)
{
    btck_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    logging_set_options(logging_options);
    logging_set_level_category(LogCategory::BENCH, LogLevel::TRACE_LEVEL);
    logging_disable_category(LogCategory::BENCH);
    logging_enable_category(LogCategory::VALIDATION);
    logging_disable_category(LogCategory::VALIDATION);

    // Check that connecting, connecting another, and then disconnecting and connecting a logger again works.
    {
        logging_set_level_category(LogCategory::KERNEL, LogLevel::TRACE_LEVEL);
        logging_enable_category(LogCategory::KERNEL);
        Logger logger{std::make_unique<TestLog>()};
        Logger logger_2{std::make_unique<TestLog>()};
    }
    Logger logger{std::make_unique<TestLog>()};
}

BOOST_AUTO_TEST_CASE(btck_context_tests)
{
    { // test default context
        Context context{};
        Context context2{};
        CheckHandle(context, context2);
    }

    { // test with context options, but not options set
        ContextOptions options{};
        Context context{options};
    }

    { // test with context options
        ContextOptions options{};
        ChainParams params{ChainType::MAINNET};
        ChainParams regtest_params{ChainType::REGTEST};
        CheckHandle(params, regtest_params);
        options.SetChainParams(params);
        options.SetNotifications(std::make_shared<TestKernelNotifications>());
        Context context{options};
    }
}

BOOST_AUTO_TEST_CASE(btck_block_header_tests)
{
    const auto block_header_data = [](std::string_view block_data) {
        return hex_string_to_byte_vec(block_data.substr(0, 160));
    };

    // Block header format: version(4) + prev_hash(32) + merkle_root(32) + timestamp(4) + bits(4) + nonce(4) = 80 bytes
    BlockHeader header_0{block_header_data(REGTEST_BLOCK_DATA[0])};
    BOOST_CHECK_EQUAL(byte_span_to_hex_string_reversed(header_0.Hash().ToBytes()), "02b546c9752f33adb2a563c6caf74b78857a0ab4214c62e057d77bed74471abf");
    BlockHeader header_1{block_header_data(REGTEST_BLOCK_DATA[1])};
    CheckHandle(header_0, header_1);

    // Test error handling for invalid data
    BOOST_CHECK_THROW(BlockHeader{hex_string_to_byte_vec("00")}, std::runtime_error);
    BOOST_CHECK_THROW(BlockHeader{hex_string_to_byte_vec("")}, std::runtime_error);

    // Test all header field accessors using a native regtest header.
    BlockHeader header{block_header_data(REGTEST_BLOCK_DATA[1])};
    BOOST_CHECK_EQUAL(header.Version(), 1);
    BOOST_CHECK_EQUAL(header.Timestamp(), 1700000001);
    BOOST_CHECK_EQUAL(header.Bits(), 0x207fffff);
    BOOST_CHECK_EQUAL(header.Nonce(), 0);
    BOOST_CHECK_EQUAL(byte_span_to_hex_string_reversed(header.Hash().ToBytes()), "635ef2420bd4cd1d55ae0855d22c5f89effb4ada14b074ae413af86f7d51563c");
    auto prev_hash = header.PrevHash();
    BOOST_CHECK_EQUAL(byte_span_to_hex_string_reversed(prev_hash.ToBytes()), "02b546c9752f33adb2a563c6caf74b78857a0ab4214c62e057d77bed74471abf");

    auto raw_block = hex_string_to_byte_vec(REGTEST_BLOCK_DATA[0]);
    Block block{raw_block};
    BlockHeader block_header{block.GetHeader()};
    BOOST_CHECK_EQUAL(block_header.Version(), 1);
    BOOST_CHECK_EQUAL(block_header.Timestamp(), 1700000000);
    BOOST_CHECK_EQUAL(block_header.Bits(), 0x207fffff);
    BOOST_CHECK_EQUAL(block_header.Nonce(), 0);
    BOOST_CHECK_EQUAL(byte_span_to_hex_string_reversed(block_header.Hash().ToBytes()), "02b546c9752f33adb2a563c6caf74b78857a0ab4214c62e057d77bed74471abf");
}

BOOST_AUTO_TEST_CASE(btck_block)
{
    Block block{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[0])};
    Block block_100{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[100])};
    CheckHandle(block, block_100);
    Block block_tx{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[205])};
    CheckRange(block_tx.Transactions(), block_tx.CountTransactions());
    auto invalid_data = hex_string_to_byte_vec("012300");
    BOOST_CHECK_THROW(Block{invalid_data}, std::runtime_error);
    auto empty_data = hex_string_to_byte_vec("");
    BOOST_CHECK_THROW(Block{empty_data}, std::runtime_error);
}

Context create_context(std::shared_ptr<TestKernelNotifications> notifications, ChainType chain_type, std::shared_ptr<TestValidationInterface> validation_interface = nullptr)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params);
    options.SetNotifications(notifications);
    if (validation_interface) {
        options.SetValidationInterface(validation_interface);
    }
    auto context{Context{options}};
    return context;
}

BOOST_AUTO_TEST_CASE(btck_chainman_tests)
{
    Logger logger{std::make_unique<TestLog>()};
    auto test_directory{TestDirectory{"chainman_test_kronein_kernel"}};

    { // test with default context
        Context context{};
        ChainstateManagerOptions chainman_opts{context, PathToString(test_directory.m_directory), PathToString(test_directory.m_directory / "blocks")};
        ChainMan chainman{context, chainman_opts};
    }

    { // test with default context options
        ContextOptions options{};
        Context context{options};
        ChainstateManagerOptions chainman_opts{context, PathToString(test_directory.m_directory), PathToString(test_directory.m_directory / "blocks")};
        ChainMan chainman{context, chainman_opts};
    }
    { // null or empty data_directory or blocks_directory are not allowed
        Context context{};
        auto valid_dir{PathToString(test_directory.m_directory)};
        std::vector<std::pair<std::string_view, std::string_view>> illegal_cases{
            {"", valid_dir},
            {valid_dir, {nullptr, 0}},
            {"", ""},
            {{nullptr, 0}, {nullptr, 0}},
        };
        for (auto& [data_dir, blocks_dir] : illegal_cases) {
            BOOST_CHECK_THROW(ChainstateManagerOptions(context, data_dir, blocks_dir),
                              std::runtime_error);
        };
    }

    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{create_context(notifications, ChainType::MAINNET)};

    ChainstateManagerOptions chainman_opts{context, PathToString(test_directory.m_directory), PathToString(test_directory.m_directory / "blocks")};
    chainman_opts.SetWorkerThreads(4);
    BOOST_CHECK(!chainman_opts.SetWipeDbs(/*wipe_block_tree=*/true, /*wipe_chainstate=*/false));
    BOOST_CHECK(chainman_opts.SetWipeDbs(/*wipe_block_tree=*/true, /*wipe_chainstate=*/true));
    BOOST_CHECK(chainman_opts.SetWipeDbs(/*wipe_block_tree=*/false, /*wipe_chainstate=*/true));
    BOOST_CHECK(chainman_opts.SetWipeDbs(/*wipe_block_tree=*/false, /*wipe_chainstate=*/false));
    ChainMan chainman{context, chainman_opts};
}

std::unique_ptr<ChainMan> create_chainman(TestDirectory& test_directory,
                                          bool reindex,
                                          bool wipe_chainstate,
                                          bool block_tree_db_in_memory,
                                          bool chainstate_db_in_memory,
                                          Context& context)
{
    ChainstateManagerOptions chainman_opts{context, PathToString(test_directory.m_directory), PathToString(test_directory.m_directory / "blocks")};

    if (reindex) {
        chainman_opts.SetWipeDbs(/*wipe_block_tree=*/reindex, /*wipe_chainstate=*/reindex);
    }
    if (wipe_chainstate) {
        chainman_opts.SetWipeDbs(/*wipe_block_tree=*/false, /*wipe_chainstate=*/wipe_chainstate);
    }
    if (block_tree_db_in_memory) {
        chainman_opts.UpdateBlockTreeDbInMemory(block_tree_db_in_memory);
    }
    if (chainstate_db_in_memory) {
        chainman_opts.UpdateChainstateDbInMemory(chainstate_db_in_memory);
    }

    auto chainman{std::make_unique<ChainMan>(context, chainman_opts)};
    return chainman;
}

void chainman_reindex_test(TestDirectory& test_directory)
{
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{create_context(notifications, ChainType::REGTEST)};
    auto chainman{create_chainman(
        test_directory, /*reindex=*/true, /*wipe_chainstate=*/false,
        /*block_tree_db_in_memory=*/false, /*chainstate_db_in_memory=*/false, context)};

    std::vector<std::string> import_files;
    BOOST_CHECK(chainman->ImportBlocks(import_files));

    // Sanity check some block retrievals
    auto chain{chainman->GetChain()};
    BOOST_CHECK_THROW(chain.GetByHeight(1000), std::runtime_error);
    auto genesis_index{chain.Entries().front()};
    BOOST_CHECK(!genesis_index.GetPrevious());
    auto genesis_block_raw{chainman->ReadBlock(genesis_index).value().ToBytes()};
    auto first_index{chain.GetByHeight(0)};
    auto first_block_raw{chainman->ReadBlock(genesis_index).value().ToBytes()};
    check_equal(genesis_block_raw, first_block_raw);
    auto height{first_index.GetHeight()};
    BOOST_CHECK_EQUAL(height, 0);

    auto next_index{chain.GetByHeight(first_index.GetHeight() + 1)};
    BOOST_CHECK(chain.Contains(next_index));
    auto next_block_data{chainman->ReadBlock(next_index).value().ToBytes()};
    auto tip_index{chain.Entries().back()};
    auto tip_block_data{chainman->ReadBlock(tip_index).value().ToBytes()};
    auto second_index{chain.GetByHeight(1)};
    auto second_block{chainman->ReadBlock(second_index).value()};
    auto second_block_data{second_block.ToBytes()};
    auto second_height{second_index.GetHeight()};
    BOOST_CHECK_EQUAL(second_height, 1);
    check_equal(next_block_data, tip_block_data);
    check_equal(next_block_data, second_block_data);

    auto second_hash{second_index.GetHash()};
    auto another_second_index{chainman->GetBlockTreeEntry(second_hash)};
    BOOST_CHECK(another_second_index);
    auto another_second_height{another_second_index->GetHeight()};
    auto second_block_hash{second_block.GetHash()};
    check_equal(second_block_hash.ToBytes(), second_hash.ToBytes());
    BOOST_CHECK_EQUAL(second_height, another_second_height);
}

void chainman_reindex_chainstate_test(TestDirectory& test_directory)
{
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{create_context(notifications, ChainType::REGTEST)};
    auto chainman{create_chainman(
        test_directory, /*reindex=*/false, /*wipe_chainstate=*/true,
        /*block_tree_db_in_memory=*/false, /*chainstate_db_in_memory=*/false, context)};

    std::vector<std::string> import_files;
    import_files.push_back(PathToString(test_directory.m_directory / "blocks" / "blk00000.dat"));
    BOOST_CHECK(chainman->ImportBlocks(import_files));
}

void chainman_regtest_validation_test(TestDirectory& test_directory)
{
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto validation_interface{std::make_shared<TestValidationInterface>()};
    auto context{create_context(notifications, ChainType::REGTEST, validation_interface)};
    auto chainman{create_chainman(
        test_directory, /*reindex=*/false, /*wipe_chainstate=*/false,
        /*block_tree_db_in_memory=*/false, /*chainstate_db_in_memory=*/false, context)};

    auto raw_block = hex_string_to_byte_vec(REGTEST_BLOCK_DATA[0]);
    Block block{raw_block};
    BlockHeader header{block.GetHeader()};
    TransactionView tx{block.GetTransaction(block.CountTransactions() - 1)};
    BOOST_CHECK_EQUAL(byte_span_to_hex_string_reversed(tx.Txid().ToBytes()), "52f4eee46d214c662780b1f9e79e62f5a88e83f096e11cd17e9fede4eab354b1");
    BOOST_CHECK_EQUAL(header.Version(), 1);
    BOOST_CHECK_EQUAL(header.Timestamp(), 1700000000);
    BOOST_CHECK_EQUAL(header.Bits(), 0x207fffff);
    BOOST_CHECK_EQUAL(header.Nonce(), 0);
    BOOST_CHECK_EQUAL(tx.CountInputs(), 1);
    Transaction tx2 = tx;
    BOOST_CHECK_EQUAL(tx2.CountInputs(), 1);
    for (auto transaction : block.Transactions()) {
        BOOST_CHECK_EQUAL(transaction.CountInputs(), 1);
    }
    auto output_counts = *(block.Transactions() | std::views::transform([](const auto& tx) {
                               return tx.CountOutputs();
                           })).begin();
    BOOST_CHECK_EQUAL(output_counts, 2);

    validation_interface->m_expected_valid_block.emplace(raw_block);
    auto ser_block{block.ToBytes()};
    check_equal(ser_block, raw_block);
    bool new_block = false;
    BOOST_CHECK(chainman->ProcessBlock(block, &new_block));
    BOOST_CHECK(new_block);

    validation_interface->m_expected_valid_block = std::nullopt;
    new_block = false;
    Block invalid_block{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[REGTEST_BLOCK_DATA.size() - 1])};
    BOOST_CHECK(!chainman->ProcessBlock(invalid_block, &new_block));
    BOOST_CHECK(!new_block);

    auto chain{chainman->GetChain()};
    BOOST_CHECK_EQUAL(chain.Height(), 1);
    auto tip{chain.Entries().back()};
    auto read_block{chainman->ReadBlock(tip)};
    BOOST_REQUIRE(read_block);
    check_equal(read_block.value().ToBytes(), raw_block);

    // Check that we can read the previous block
    BlockTreeEntry tip_2{*tip.GetPrevious()};
    Block read_block_2{*chainman->ReadBlock(tip_2)};
    BOOST_CHECK_EQUAL(chainman->ReadBlockSpentOutputs(tip_2).Count(), 0);
    BOOST_CHECK_EQUAL(chainman->ReadBlockSpentOutputs(tip).Count(), 0);

    // It should be an error if we go another block back, since the genesis has no ancestor
    BOOST_CHECK(!tip_2.GetPrevious());

    // If we try to validate it again, it should be a duplicate
    BOOST_CHECK(chainman->ProcessBlock(block, &new_block));
    BOOST_CHECK(!new_block);
}

BOOST_AUTO_TEST_CASE(btck_chainman_regtest_disk_tests)
{
    auto test_directory{TestDirectory{"regtest_disk_test_kronein_kernel"}};
    chainman_regtest_validation_test(test_directory);
    chainman_reindex_test(test_directory);
    chainman_reindex_chainstate_test(test_directory);
}

BOOST_AUTO_TEST_CASE(btck_block_hash_tests)
{
    std::array<std::byte, 32> test_hash;
    std::array<std::byte, 32> test_hash_2;
    for (int i = 0; i < 32; ++i) {
        test_hash[i] = static_cast<std::byte>(i);
        test_hash_2[i] = static_cast<std::byte>(i + 1);
    }
    BlockHash block_hash{test_hash};
    BlockHash block_hash_2{test_hash_2};
    BOOST_CHECK(block_hash != block_hash_2);
    BOOST_CHECK(block_hash == block_hash);
    CheckHandle(block_hash, block_hash_2);
}

BOOST_AUTO_TEST_CASE(btck_block_tree_entry_tests)
{
    auto test_directory{TestDirectory{"block_tree_entry_test_kronein_kernel"}};
    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{create_context(notifications, ChainType::REGTEST)};
    auto chainman{create_chainman(
        test_directory,
        /*reindex=*/false,
        /*wipe_chainstate=*/false,
        /*block_tree_db_in_memory=*/true,
        /*chainstate_db_in_memory=*/true,
        context)};

    // Process a couple of blocks
    for (size_t i{0}; i < 3; i++) {
        Block block{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[i])};
        bool new_block{false};
        chainman->ProcessBlock(block, &new_block);
        BOOST_CHECK(new_block);
    }

    auto chain{chainman->GetChain()};
    auto entry_0{chain.GetByHeight(0)};
    auto entry_1{chain.GetByHeight(1)};
    auto entry_2{chain.GetByHeight(2)};

    // Test inequality
    BOOST_CHECK(entry_0 != entry_1);
    BOOST_CHECK(entry_1 != entry_2);
    BOOST_CHECK(entry_0 != entry_2);

    // Test equality with same entry
    BOOST_CHECK(entry_0 == chain.GetByHeight(0));
    BOOST_CHECK(entry_0 == BlockTreeEntry{entry_0});
    BOOST_CHECK(entry_1 == entry_1);

    // Test GetPrevious
    auto prev{entry_1.GetPrevious()};
    BOOST_CHECK(prev.has_value());
    BOOST_CHECK(prev.value() == entry_0);
}

BOOST_AUTO_TEST_CASE(btck_chainman_in_memory_tests)
{
    auto in_memory_test_directory{TestDirectory{"in-memory_test_kronein_kernel"}};

    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{create_context(notifications, ChainType::REGTEST)};
    auto chainman{create_chainman(
        in_memory_test_directory, /*reindex=*/false, /*wipe_chainstate=*/false,
        /*block_tree_db_in_memory=*/true, /*chainstate_db_in_memory=*/true, context)};

    for (auto& raw_block : REGTEST_BLOCK_DATA) {
        Block block{hex_string_to_byte_vec(raw_block)};
        bool new_block{false};
        chainman->ProcessBlock(block, &new_block);
        BOOST_CHECK(new_block);
    }

    BOOST_CHECK(fs::exists(in_memory_test_directory.m_directory / "blocks"));
    BOOST_CHECK(!fs::exists(in_memory_test_directory.m_directory / "blocks" / "index"));
    BOOST_CHECK(!fs::exists(in_memory_test_directory.m_directory / "chainstate"));

    BOOST_CHECK(context.interrupt());
}

BOOST_AUTO_TEST_CASE(btck_chainman_regtest_tests)
{
    auto test_directory{TestDirectory{"regtest_test_kronein_kernel"}};

    auto notifications{std::make_shared<TestKernelNotifications>()};
    auto context{create_context(notifications, ChainType::REGTEST)};

    {
        auto chainman{create_chainman(
            test_directory, /*reindex=*/false, /*wipe_chainstate=*/false,
            /*block_tree_db_in_memory=*/false, /*chainstate_db_in_memory=*/false, context)};
        for (const auto& data : REGTEST_BLOCK_DATA) {
            Block block{hex_string_to_byte_vec(data)};
            BlockHeader header = block.GetHeader();
            BlockValidationState state{};
            BOOST_CHECK(state.GetBlockValidationResult() == BlockValidationResult::UNSET);
            BOOST_CHECK(chainman->ProcessBlockHeader(header, state));
            BOOST_CHECK(state.GetValidationMode() == ValidationMode::VALID);
            BlockTreeEntry entry{*chainman->GetBlockTreeEntry(header.Hash())};
            BOOST_CHECK(!chainman->GetChain().Contains(entry));
            BlockTreeEntry best_entry{chainman->GetBestEntry()};
            BlockHash hash{entry.GetHash()};
            BOOST_CHECK(hash == best_entry.GetHeader().Hash());
        }
    }

    // Validate 206 regtest blocks in total.
    // Stop halfway to check that it is possible to continue validating starting
    // from prior state.
    const size_t mid{REGTEST_BLOCK_DATA.size() / 2};

    {
        auto chainman{create_chainman(
            test_directory, /*reindex=*/false, /*wipe_chainstate=*/false,
            /*block_tree_db_in_memory=*/false, /*chainstate_db_in_memory=*/false, context)};
        for (size_t i{0}; i < mid; i++) {
            Block block{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[i])};
            bool new_block{false};
            BOOST_CHECK(chainman->ProcessBlock(block, &new_block));
            BOOST_CHECK(new_block);
        }
    }

    auto chainman{create_chainman(
        test_directory, /*reindex=*/false, /*wipe_chainstate=*/false,
        /*block_tree_db_in_memory=*/false, /*chainstate_db_in_memory=*/false, context)};

    for (size_t i{mid}; i < REGTEST_BLOCK_DATA.size(); i++) {
        Block block{hex_string_to_byte_vec(REGTEST_BLOCK_DATA[i])};
        bool new_block{false};
        BOOST_CHECK(chainman->ProcessBlock(block, &new_block));
        BOOST_CHECK(new_block);
    }

    auto chain = chainman->GetChain();
    auto tip = chain.Entries().back();
    auto read_block = chainman->ReadBlock(tip).value();
    check_equal(read_block.ToBytes(), hex_string_to_byte_vec(REGTEST_BLOCK_DATA[REGTEST_BLOCK_DATA.size() - 1]));

    auto tip_2 = tip.GetPrevious().value();
    auto read_block_2 = chainman->ReadBlock(tip_2).value();
    check_equal(read_block_2.ToBytes(), hex_string_to_byte_vec(REGTEST_BLOCK_DATA[REGTEST_BLOCK_DATA.size() - 2]));

    Txid txid = read_block.Transactions()[0].Txid();
    Txid txid_2 = read_block_2.Transactions()[0].Txid();
    BOOST_CHECK(txid != txid_2);
    BOOST_CHECK(txid == txid);
    CheckHandle(txid, txid_2);

    auto find_transaction = [&chainman](const TxidView& target_txid) -> std::optional<Transaction> {
        auto chain = chainman->GetChain();
        for (const auto block_tree_entry : chain.Entries()) {
            auto block{chainman->ReadBlock(block_tree_entry)};
            for (const TransactionView transaction : block->Transactions()) {
                if (transaction.Txid() == target_txid) {
                    return Transaction{transaction};
                }
            }
        }
        return std::nullopt;
    };

    for (const auto block_tree_entry : chain.Entries()) {
        auto block{chainman->ReadBlock(block_tree_entry)};
        for (const auto transaction : block->Transactions()) {
            std::vector<TransactionInput> inputs;
            std::vector<TransactionOutput> spent_outputs;
            for (const auto input : transaction.Inputs()) {
                OutPointView point = input.OutPoint();
                if (point.index() == std::numeric_limits<uint32_t>::max()) {
                    continue;
                }
                inputs.emplace_back(input);
                BOOST_CHECK(point.Txid() != transaction.Txid());
                std::optional<Transaction> tx = find_transaction(point.Txid());
                BOOST_CHECK(tx.has_value());
                BOOST_CHECK(point.Txid() == tx->Txid());
                spent_outputs.emplace_back(tx->GetOutput(point.index()));
            }
            BOOST_CHECK(inputs.size() == spent_outputs.size());
            ScriptVerifyStatus status = ScriptVerifyStatus::OK;
            const PrecomputedTransactionData precomputed_txdata{transaction, spent_outputs};
            for (size_t i{0}; i < inputs.size(); ++i) {
                BOOST_CHECK(spent_outputs[i].GetScriptPubkey().Verify(transaction, &precomputed_txdata, i, status));
            }
        }
    }

    // Read spent outputs for current tip and its previous block
    BlockSpentOutputs block_spent_outputs{chainman->ReadBlockSpentOutputs(tip)};
    BlockSpentOutputs block_spent_outputs_prev{chainman->ReadBlockSpentOutputs(*tip.GetPrevious())};
    CheckHandle(block_spent_outputs, block_spent_outputs_prev);
    CheckRange(block_spent_outputs_prev.TxsSpentOutputs(), block_spent_outputs_prev.Count());
    BOOST_CHECK_EQUAL(block_spent_outputs.Count(), 1);

    // Get transaction spent outputs from the last transaction in the two blocks
    TransactionSpentOutputsView transaction_spent_outputs{block_spent_outputs.GetTxSpentOutputs(block_spent_outputs.Count() - 1)};
    TransactionSpentOutputs owned_transaction_spent_outputs{transaction_spent_outputs};
    TransactionSpentOutputs owned_transaction_spent_outputs_prev{block_spent_outputs_prev.GetTxSpentOutputs(block_spent_outputs_prev.Count() - 1)};
    CheckHandle(owned_transaction_spent_outputs, owned_transaction_spent_outputs_prev);
    CheckRange(transaction_spent_outputs.Coins(), transaction_spent_outputs.Count());

    // Get the last coin from the transaction spent outputs
    CoinView coin{transaction_spent_outputs.GetCoin(transaction_spent_outputs.Count() - 1)};
    BOOST_CHECK(!coin.IsCoinbase());
    Coin owned_coin{coin};
    Coin owned_coin_prev{owned_transaction_spent_outputs_prev.GetCoin(owned_transaction_spent_outputs_prev.Count() - 1)};
    CheckHandle(owned_coin, owned_coin_prev);

    // Validate coin properties
    TransactionOutputView output = coin.GetOutput();
    uint32_t coin_height = coin.GetConfirmationHeight();
    BOOST_CHECK_EQUAL(coin_height, 205);
    BOOST_CHECK_EQUAL(output.Amount(), 100000000);

    // Test script pubkey serialization
    auto script_pubkey = output.GetScriptPubkey();
    auto script_pubkey_bytes{script_pubkey.ToBytes()};
    BOOST_CHECK_EQUAL(script_pubkey_bytes.size(), 34);
    auto round_trip_script_pubkey{ScriptPubkey(script_pubkey_bytes)};
    BOOST_CHECK_EQUAL(round_trip_script_pubkey.ToBytes().size(), 34);

    for (const auto tx_spent_outputs : block_spent_outputs.TxsSpentOutputs()) {
        for (const auto coins : tx_spent_outputs.Coins()) {
            BOOST_CHECK_GT(coins.GetOutput().Amount(), 1);
        }
    }

    CheckRange(chain.Entries(), chain.CountEntries());

    for (const BlockTreeEntry entry : chain.Entries()) {
        std::optional<Block> block{chainman->ReadBlock(entry)};
        if (block) {
            for (const TransactionView transaction : block->Transactions()) {
                for (const TransactionOutputView output : transaction.Outputs()) {
                    // skip data carrier outputs
                    if ((unsigned char)output.GetScriptPubkey().ToBytes()[0] == 0x6a) {
                        continue;
                    }
                    BOOST_CHECK_GT(output.Amount(), 1);
                }
            }
        }
    }

    int32_t count{0};
    for (const auto entry : chain.Entries()) {
        BOOST_CHECK_EQUAL(entry.GetHeight(), count);
        ++count;
    }
    BOOST_CHECK_EQUAL(count, chain.CountEntries());


    fs::remove_all(test_directory.m_directory / "blocks" / "blk00000.dat");
    BOOST_CHECK(!chainman->ReadBlock(tip_2).has_value());
    fs::remove_all(test_directory.m_directory / "blocks" / "rev00000.dat");
    BOOST_CHECK_THROW(chainman->ReadBlockSpentOutputs(tip), std::runtime_error);
}
