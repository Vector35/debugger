#include <gtest/gtest.h>
#include <array>
#include "dbgengadapter.h"

const std::array<std::string, 5> test_bins{ "helloworld_x64-windows.exe",
                                            "helloworld_func_x64-windows.exe",
                                            "helloworld_loop_x64-windows.exe",
                                            "missing_switch_case_x64-windows.exe",
                                            "do_exception_pie_x64-windows.exe" };

#ifdef WIN32
TEST(DbgEngineTest, CorrectExecute) {
    DbgEngAdapter debug_adapter{};

    for ( const auto& bin : test_bins ) {
        ASSERT_TRUE(debug_adapter.Execute(bin));
        ASSERT_NO_THROW(debug_adapter.Quit());
    }
}

TEST(DbgEngineTest, IncorrectExecute) {
    DbgEngAdapter debug_adapter{};

    ASSERT_FALSE(debug_adapter.Execute("this bin does not exist"));
    ASSERT_FALSE(debug_adapter.Execute("doesnotexistbin.exe"));
}
#endif