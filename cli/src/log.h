#pragma once
#include <iostream>
#include <windows.h>

namespace Log
{
    enum Mode : std::uint8_t
    {
        None,
        Success,
        Info,
        Warning,
        Error,
    };

    struct Style
    {
        float m_red{1.f}, m_green{1.f}, m_blue{1.f};

        Style() = default;

        Style(float red, float green, float blue)
            : m_red(red), m_green(green), m_blue(blue) {}

        [[nodiscard]] std::string AsAnsi() const
        {
            std::string out{};
            out.reserve(64);

            std::sprintf(out.data(), "\x1b[38;2;%0.f;%0.f;%0.fm", this->m_red, this->m_green, this->m_blue);

            return out;
        }
    };

    inline void SetupAnsi()
    {
        const auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        const auto err_handle = GetStdHandle(STD_ERROR_HANDLE);
        if (!out_handle || !err_handle)
            return;

        unsigned long old_out_mode{}, old_err_mode{};
        if ( !GetConsoleMode(out_handle, &old_out_mode) || !GetConsoleMode(err_handle, &old_err_mode) )
            return;

        SetConsoleMode(out_handle, old_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleMode(err_handle, old_err_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    template <Mode LogMode = Mode::None, typename... Args>
    int print(const std::string_view str, Args... args )
    {
        if constexpr ( LogMode == Mode::Success )
            printf("%s", Style( 0, 255, 0 ).AsAnsi().c_str());

        if constexpr ( LogMode == Mode::Info )
            printf("%s", Style( 30, 255, 255 ).AsAnsi().c_str());

        if constexpr ( LogMode == Mode::Warning )
            printf("%s", Style( 255, 255, 0 ).AsAnsi().c_str());

        if constexpr ( LogMode == Mode::Error )
            printf("%s", Style( 255, 0, 0 ).AsAnsi().c_str());

        printf(str.data(), std::forward<Args>(args)...);
        return printf("\033[0m");
    }
}