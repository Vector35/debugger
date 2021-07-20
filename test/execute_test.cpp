#include <gtest/gtest.h>
#include <array>
#include <thread>
#include <chrono>
#include <fstream>

#ifdef WIN32
#include "dbgengadapter.h"

const std::array<std::string, 5> test_bins{ "helloworld_x64-windows.exe",
                                            "helloworld_func_x64-windows.exe",
                                            "helloworld_loop_x64-windows.exe",
                                            "missing_switch_case_x64-windows.exe",
                                            "do_exception_pie_x64-windows.exe" };


std::uintptr_t GetPEEntry(const std::string& file_name) {
    std::ifstream file(file_name, std::ios::binary);
    std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(file), {});

    const auto dos_header = (IMAGE_DOS_HEADER*)data.data();
    const auto nt_headers = (IMAGE_NT_HEADERS*)((std::uintptr_t)data.data() + dos_header->e_lfanew);
    return nt_headers->OptionalHeader.ImageBase + nt_headers->OptionalHeader.AddressOfEntryPoint;
}

TEST(DbgEngineTest, CorrectExecute) {
    DbgEngAdapter debug_adapter{};

    for ( const auto& bin : test_bins ) {
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

    for ( const auto& bin : test_bins ) {
        if (bin == "do_exception_pie_x64-windows.exe")
            continue;

        ASSERT_TRUE( debug_adapter.Execute( bin ));
        const auto entry_breakpoint = debug_adapter.AddBreakpoint( GetPEEntry( bin ));
        ASSERT_TRUE( debug_adapter.Go());
        ASSERT_EQ( debug_adapter.StopReason(), DebugStopReason::Breakpoint );
        ASSERT_TRUE( debug_adapter.RemoveBreakpoint( entry_breakpoint ));
        ASSERT_NO_THROW(debug_adapter.Quit());
    }
}

TEST(DbgEngineTest, ExceptionTests) {
    DbgEngAdapter debug_adapter{};

    const auto exception_bin = "do_exception_pie_x64-windows.exe";
    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_bin, { "segfault" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_bin, { "illegalinstr" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(DbgEngineTest, BreakIn) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(test_bins[2]));

    std::thread([&](){
        debug_adapter.Go();
    }).detach();

    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    ASSERT_TRUE(debug_adapter.BreakInto());
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(DbgEngineTest, ThreadList) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(test_bins[2]));
    ASSERT_NE(debug_adapter.GetThreadList().size(), 0);
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(DbgEngineTest, ModuleList) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(test_bins[2]));
    ASSERT_NE(debug_adapter.GetModuleList().size(), 0);
    ASSERT_NO_THROW(debug_adapter.Quit());
}
#else
#include "gdbadapter.h"
#include <elf.h>

const std::array<std::string, 5> test_bins{ "helloworld_x64-linux",
                                            "helloworld_func_x64-linux",
                                            "helloworld_loop_x64-linux",
                                            "missing_switch_case_x64-linux",
                                            "do_exception_pie_x64-linux" };

std::uintptr_t GetELFEntry(const std::string& file_name) {
    std::ifstream file(file_name, std::ios::binary);
    std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(file), {});

    const auto ehdr = (Elf64_Ehdr*)data.data();
    return ehdr->e_entry;
}

TEST(GdbTest, CorrectExecute) {
    GdbAdapter debug_adapter{};

    for ( const auto& bin : test_bins ) {
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

    for ( const auto& bin : test_bins ) {
        if (bin == "do_exception_pie_x64-linux")
            continue;

        ASSERT_TRUE( debug_adapter.Execute( bin ));
        const auto entry_breakpoint = debug_adapter.AddBreakpoint( GetELFEntry( bin ));
        ASSERT_TRUE( debug_adapter.Go());
        ASSERT_EQ( debug_adapter.StopReason(), DebugStopReason::Breakpoint );
        ASSERT_TRUE( debug_adapter.RemoveBreakpoint( entry_breakpoint ));
        ASSERT_NO_THROW(debug_adapter.Quit());
    }
}

TEST(GdbTest, ExceptionTests) {
    GdbAdapter debug_adapter{};

    const auto exception_bin = "do_exception_pie_x64-linux";
    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_bin, { "segfault" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( exception_bin, { "illegalinstr" } ));
    ASSERT_TRUE(debug_adapter.Go());
    ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::AccessViolation);
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(GdbTest, BreakIn) {
    GdbAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(test_bins[2]));

    std::thread([&](){
        debug_adapter.Go();
    }).detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    ASSERT_TRUE(debug_adapter.BreakInto());
    ASSERT_NO_THROW(debug_adapter.Quit());
}

TEST(GdbTest, ThreadList) {
    GdbAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(test_bins[2]));
    ASSERT_NE(debug_adapter.GetThreadList().size(), 0);
    ASSERT_NO_THROW(debug_adapter.Quit());
}
#endif