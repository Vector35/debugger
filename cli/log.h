/*
Copyright 2020-2022 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once
#include <iostream>
#include "binaryninjaapi.h"
#ifdef WIN32
#include <windows.h>
#endif
#include "fmt/format.h"

namespace Log
{
    enum Mode : std::int8_t
    {
        None = -1,
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3,
        Alert = 4
    };

    struct Style
    {
        float m_red{255.f}, m_green{255.f}, m_blue{255.f};

        Style() = default;

        Style(float red, float green, float blue)
            : m_red(red), m_green(green), m_blue(blue) {}

        [[nodiscard]] std::string AsAnsi() const {
            return fmt::format("\x1b[38;2;{:.0f};{:.0f};{:.0f}m", this->m_red, this->m_green, this->m_blue);
        }
    };

    inline void SetupAnsi()
    {
#ifdef WIN32
        const auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        const auto err_handle = GetStdHandle(STD_ERROR_HANDLE);
        if (!out_handle || !err_handle)
            return;

        unsigned long old_out_mode{}, old_err_mode{};
        if ( !GetConsoleMode(out_handle, &old_out_mode) || !GetConsoleMode(err_handle, &old_err_mode) )
            return;

        SetConsoleMode(out_handle, old_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleMode(err_handle, old_err_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
    }

    template <Mode LogMode = Mode::None, typename... Args>
    bool print(const std::string_view str, Args... args )
    {
        if constexpr (LogMode == Mode::Debug)
            fmt::print("[{}DEBUG\033[0m] {}",
                       Style(173, 216, 230),
                       Style(173, 216, 230));

        if constexpr (LogMode == Mode::Info)
            fmt::print("[{}INFO\033[0m] {}",
                       Style(144, 238, 144),
                       Style(144, 238, 144));

        if constexpr (LogMode == Mode::Warning)
            fmt::print("[{}WARNING\033[0m] {}",
                       Style(255, 255, 224),
                       Style(255, 255, 224));

        if constexpr (LogMode == Mode::Error)
            fmt::print("[{}ERROR\033[0m] {}",
                       Style(255, 114, 118),
                       Style(255, 114, 118));

        if constexpr (LogMode == Mode::Alert)
            fmt::print("[{}ALERT\033[0m] {}",
                       Style(255, 0, 0),
                       Style(255, 0, 0));

        fmt::print(str.data(), std::forward<Args>(args)...);
        fmt::print("\033[0m");

        if constexpr (LogMode != Mode::None)
        {
            const auto binja_string = fmt::format("[BINARYNINJA] {}",
                                                  fmt::format(str.data(), std::forward<Args>(args)...));
            BinaryNinja::Log(static_cast<BNLogLevel>(LogMode), binja_string.c_str());
        }

        return true;
    }
}

/* overloading Log::Style for fmtlib so that we don't need to call .AsAnsi() when formatting */
template <> struct fmt::formatter<Log::Style> {
    char presentation = 'a';
    constexpr auto parse(fmt::format_parse_context& ctx) -> decltype(ctx.begin()) {
        auto it = ctx.begin(), end = ctx.end();
        if (it != end && (*it == 'a')) presentation = *it++;

        if (it != end && *it != '}')
            throw fmt::format_error("invalid format");

        return it;
    }

    template <typename FormatContext>
    auto format(const Log::Style& style, FormatContext& ctx) -> decltype(ctx.out()) {
        return format_to( ctx.out(), "{}", style.AsAnsi() );
    }
};