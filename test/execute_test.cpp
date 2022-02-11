#include <gtest/gtest.h>
#include <array>
#include <thread>
#include <chrono>
#include <fstream>

#if __has_include(<filesystem>)
    #include <filesystem>
#elif __has_include(<experimental/filesystem>)
    #include <experimental/filesystem>
    namespace std {
        namespace filesystem = experimental::filesystem;
    }
#endif

std::vector<std::string> CollectTestBins() {
    static std::vector<std::string> valid_testbins{};
    if (!valid_testbins.empty())
        return valid_testbins;

    const std::vector<std::string> whitelisted_extensions{
            ".exe", ""
    };

    auto directory_iterator = std::filesystem::directory_iterator(std::filesystem::current_path());
    for (const auto& file : directory_iterator) {
        if (std::find(whitelisted_extensions.begin(), whitelisted_extensions.end(), file.path().extension()) == whitelisted_extensions.end() ||
            file.is_directory() ||
            file.path().string().find("Makefile") != std::string::npos ||
            file.path().string().find("execute_test") != std::string::npos )
            continue;

        const auto check_perms = [](const std::filesystem::perms& perm, const std::vector<std::filesystem::perms>& checks) {
            return std::all_of(checks.cbegin(), checks.cend(), [&](const std::filesystem::perms check) {
                return (perm & check) != std::filesystem::perms::none;
            });
        };

        if (!check_perms(std::filesystem::status(file).permissions(), {std::filesystem::perms::owner_exec, std::filesystem::perms::group_exec, std::filesystem::perms::others_exec}))
            continue;

        valid_testbins.push_back(file.path().string());
    }

    return valid_testbins;
}

std::string FindLoopBin() {
    static std::string loop_file{};
    if (!loop_file.empty())
        return loop_file;

    const auto test_bins = CollectTestBins();
    for (const auto& bin : test_bins ) {
        if (bin.find("loop") != std::string::npos) {
            loop_file = bin;
            break;
        }
    }

    return loop_file;
}

#ifdef WIN32
#include "dbgengadapter.h"

std::uintptr_t GetPEEntry(const std::string& file_name) {
    std::ifstream file(file_name, std::ios::binary);
    std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(file), {});

    const auto dos_header = (IMAGE_DOS_HEADER*)data.data();
    const auto nt_headers = (IMAGE_NT_HEADERS*)((std::uintptr_t)data.data() + dos_header->e_lfanew);
    file.close();

    return nt_headers->OptionalHeader.ImageBase + nt_headers->OptionalHeader.AddressOfEntryPoint;
}

TEST(DbgEngineTest, CorrectExecute) {
    DbgEngAdapter debug_adapter{};

    for ( const auto& bin : CollectTestBins() ) {
        ASSERT_TRUE(debug_adapter.Execute(bin)) << "Execute failed on [" + bin + "]";
        ASSERT_NO_THROW(debug_adapter.Quit()) << "Quit threw an exception";
    }
}

TEST(DbgEngineTest, IncorrectExecute) {
    DbgEngAdapter debug_adapter{};

    ASSERT_FALSE(debug_adapter.Execute("this bin does not exist"));
    ASSERT_FALSE(debug_adapter.Execute("doesnotexistbin.exe"));
}

TEST(DbgEngineTest, BreakpointTest) {
    DbgEngAdapter debug_adapter{};

    for ( const auto& bin : CollectTestBins() ) {
        if (bin.find("pie") != std::string::npos )
            continue;

        ASSERT_TRUE( debug_adapter.Execute( bin ));
        const auto entry_breakpoint = debug_adapter.AddBreakpoint( GetPEEntry( bin ));
        ASSERT_TRUE( debug_adapter.Go());

        if (bin.find("hh1") != std::string::npos) {
            ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::Unknown);
            ASSERT_FALSE(debug_adapter.RemoveBreakpoint( entry_breakpoint ));
            ASSERT_NO_THROW(debug_adapter.Quit());
            continue;
        }

        ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::Breakpoint);
        ASSERT_TRUE( debug_adapter.RemoveBreakpoint( entry_breakpoint ));
        ASSERT_NO_THROW(debug_adapter.Quit());
    }
}

TEST(DbgEngineTest, ExceptionTests) {
    DbgEngAdapter debug_adapter{};

    std::string exception_file{};
    const auto test_bins = CollectTestBins();
    for (const auto& bin : test_bins ) {
        if (bin.find("exception") != std::string::npos) {
            exception_file = bin;
            break;
        }
    }

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_file, { "segfault" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_file, { "illegalinstr" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(DbgEngineTest, BreakIn) {
    DbgEngAdapter debug_adapter{};

    fmt::print("{}", FindLoopBin());
    ASSERT_TRUE(debug_adapter.Execute(FindLoopBin()));

    std::thread([&](){
        debug_adapter.Go();
    }).detach();

    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    ASSERT_TRUE(debug_adapter.BreakInto());
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(DbgEngineTest, ThreadList) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(FindLoopBin()));
    ASSERT_NE(debug_adapter.GetThreadList().size(), 0);
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(DbgEngineTest, ModuleList) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(FindLoopBin()));
    ASSERT_NE(debug_adapter.GetModuleList().size(), 0);
    ASSERT_NO_THROW(debug_adapter.Quit());
}
#else
#include "gdbadapter.h"
#include <elf.h>

std::uintptr_t GetELFEntry(const std::string& file_name) {
    std::ifstream file(file_name, std::ios::binary);
    std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(file), {});

    const auto ehdr = (Elf64_Ehdr*)data.data();
    return ehdr->e_entry;
}

TEST(GdbTest, CorrectExecute) {
    GdbAdapter debug_adapter{};

    for ( const auto& bin : CollectTestBins() ) {
        ASSERT_TRUE(debug_adapter.Execute(bin)) << "Execute failed on [" + bin + "]";
        ASSERT_NO_THROW(debug_adapter.Quit()) << "Quit threw an exception";
    }
}

TEST(GdbTest, IncorrectExecute) {
    GdbAdapter debug_adapter{};

    ASSERT_FALSE(debug_adapter.Execute("this bin does not exist"));
    ASSERT_FALSE(debug_adapter.Execute("doesnotexistbin.exe"));
}

TEST(GdbTest, BreakpointTest) {
    GdbAdapter debug_adapter{};

    for ( const auto& bin : CollectTestBins() ) {
        if (bin.find("pie") != std::string::npos )
            continue;

        ASSERT_TRUE( debug_adapter.Execute( bin ));
        const auto entry_breakpoint = debug_adapter.AddBreakpoint( GetELFEntry( bin ));
        ASSERT_TRUE( debug_adapter.Go());

        if (bin.find("hh1") != std::string::npos) {
            ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::Unknown);
            ASSERT_FALSE(debug_adapter.RemoveBreakpoint( entry_breakpoint ));
            ASSERT_NO_THROW(debug_adapter.Quit());
            continue;
        }

        ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::Breakpoint);
        ASSERT_TRUE( debug_adapter.RemoveBreakpoint( entry_breakpoint ));
        ASSERT_NO_THROW(debug_adapter.Quit());
    }
}

TEST(GdbTest, ExceptionTests) {
    GdbAdapter debug_adapter{};

    std::string exception_file{};
    const auto test_bins = CollectTestBins();
    for (const auto& bin : test_bins ) {
        if (bin.find("exception") != std::string::npos) {
            exception_file = bin;
            break;
        }
    }

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_file, { "segfault" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_file, { "illegalinstr" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(GdbTest, BreakIn) {
    GdbAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(FindLoopBin()));

    std::thread([&](){
        debug_adapter.Go();
    }).detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    ASSERT_TRUE(debug_adapter.BreakInto());
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(GdbTest, ThreadList) {
    GdbAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(FindLoopBin()));
    ASSERT_NE(debug_adapter.GetThreadList().size(), 0);
    ASSERT_NO_THROW(debug_adapter.Quit());
}
#endif