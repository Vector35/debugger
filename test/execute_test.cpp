#include <gtest/gtest.h>
#include <array>
#include <thread>
#include <chrono>
#include "dbgengadapter.h"

const std::array<std::string, 5> test_bins{ "helloworld_x64-windows.exe",
                                            "helloworld_func_x64-windows.exe",
                                            "helloworld_loop_x64-windows.exe",
                                            "missing_switch_case_x64-windows.exe",
                                            "do_exception_pie_x64-windows.exe" };

#ifdef WIN32
TEST(DbgEngineTest, EnableColoredLog) {
    const auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto err_handle = GetStdHandle(STD_ERROR_HANDLE);

    unsigned long old_out_mode{}, old_err_mode{};
    ASSERT_TRUE(GetConsoleMode(out_handle, &old_out_mode));
    ASSERT_TRUE(GetConsoleMode(err_handle, &old_err_mode));

    ASSERT_TRUE(SetConsoleMode(out_handle, old_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING));
    ASSERT_TRUE(SetConsoleMode(err_handle, old_err_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING));
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

TEST(DbgEngineTest, BreakIn) {
    DbgEngAdapter debug_adapter{};

    ASSERT_TRUE(debug_adapter.Execute(test_bins[2]));

    std::thread([&](){
        std::this_thread::sleep_for(std::chrono::nanoseconds(1));
        ASSERT_TRUE(debug_adapter.BreakInto());
    }).detach();

    ASSERT_TRUE(debug_adapter.Go());
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