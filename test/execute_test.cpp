#include <gtest/gtest.h>
#include <array>
#include <thread>
#include <chrono>
#include <fstream>

const std::array<std::string, 5> test_bins{ "helloworld_x64-windows.exe",
                                            "helloworld_func_x64-windows.exe",
                                            "helloworld_loop_x64-windows.exe",
                                            "missing_switch_case_x64-windows.exe",
                                            "do_exception_pie_x64-windows.exe" };

#ifdef WIN32
#include "dbgengadapter.h"

std::uintptr_t GetPEEntry(const std::string& file_name) {
    std::ifstream file(file_name, std::ios::binary);
    std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(file), {});

    const auto dos_header = (IMAGE_DOS_HEADER*)data.data();
    const auto nt_headers = (IMAGE_NT_HEADERS*)((std::uintptr_t)data.data() + dos_header->e_lfanew);
    return nt_headers->OptionalHeader.ImageBase + nt_headers->OptionalHeader.AddressOfEntryPoint;
}

TEST(DbgEngineTest, EnableColoredLog) {
    const auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto err_handle = GetStdHandle(STD_ERROR_HANDLE);

    unsigned long old_out_mode{}, old_err_mode{};
    GetConsoleMode(out_handle, &old_out_mode);
    GetConsoleMode(err_handle, &old_err_mode);

    SetConsoleMode(out_handle, old_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleMode(err_handle, old_err_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
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

TEST(DbgEngineTest, CorrectAttach) {
    DbgEngAdapter debug_adapter{};

    return;

    STARTUPINFOA startup_info{};
    PROCESS_INFORMATION process_info{};
    ASSERT_TRUE(CreateProcessA(test_bins[2].c_str(), nullptr, nullptr, nullptr,
                               true, CREATE_NEW_CONSOLE, nullptr, nullptr,
                               &startup_info, &process_info));
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);

    ASSERT_TRUE(debug_adapter.Attach(process_info.dwProcessId)) << "Attach failed";

    for (std::size_t index{}; index < 4; index++) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (index)
            ASSERT_TRUE(debug_adapter.BreakInto());
        for (const auto& [reg_name, value] : debug_adapter.ReadAllRegisters())
            fmt::print("{}: ({} bits): {:#X}\n", reg_name, value.m_width, value.m_value);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::thread([&](){
            debug_adapter.Go();
        }).detach();
    }

    ASSERT_NO_THROW(debug_adapter.Detach());
}

TEST(DbgEngineTest, StepTest) {
    DbgEngAdapter debug_adapter{};

    for ( const auto& bin : test_bins ) {
        if (bin == "helloworld_loop_x64-windows.exe")
            continue;

        ASSERT_TRUE( debug_adapter.Execute( bin ));
        const auto entry_breakpoint = debug_adapter.AddBreakpoint( GetPEEntry( bin ));
        ASSERT_TRUE( debug_adapter.Go());
        ASSERT_EQ( debug_adapter.StopReason(), DebugStopReason::Breakpoint );
        ASSERT_TRUE( debug_adapter.RemoveBreakpoint( entry_breakpoint ));
        ASSERT_TRUE( debug_adapter.StepInto());
        ASSERT_EQ( debug_adapter.StopReason(), DebugStopReason::SingleStep );
        ASSERT_TRUE( debug_adapter.StepInto());
        ASSERT_EQ( debug_adapter.StopReason(), DebugStopReason::SingleStep );
        ASSERT_TRUE( debug_adapter.StepInto());
        ASSERT_EQ( debug_adapter.StopReason(), DebugStopReason::SingleStep );
        ASSERT_TRUE(debug_adapter.Go());
        ASSERT_EQ(debug_adapter.StopReason(), DebugStopReason::ProcessExited);
        ASSERT_NO_THROW(debug_adapter.Quit());
    }
}

TEST(DbgEngineTest, ExceptionTests) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE( debug_adapter.ExecuteWithArgs( "do_exception_pie_x64-windows.exe", { "segfault" } ));
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
#endif