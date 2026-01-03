#include <format>
#include <iostream>
#include <memory>

#include "shared_ctx.hpp"

void append_report_to_queue(
        std::uint32_t message_id, const wchar_t* str1, std::uint32_t str1_len, const wchar_t* str2,
        std::uint32_t str2_len, const std::uint8_t* data, std::uint32_t data_len
) {

    std::wcout << std::format(L"[{:#x}]:\n", message_id);

    if (str1) {
        const std::wstring_view str1_view{str1, static_cast<size_t>(str1_len)};
        std::wcout << std::format(L"  1-'{}'\n", str1_view);
    }
    if (str2) {
        const std::wstring_view str2_view{str2, static_cast<size_t>(str2_len)};
        std::wcout << std::format(L"  2-'{}'\n", str2_view);
    }

    if (data) {
        constexpr int bytes_per_line = 8;
        constexpr int hex_field_width = bytes_per_line * 2 + (bytes_per_line - 1); // 23

        for (std::uint32_t i = 0; i < data_len; i += bytes_per_line) {
            std::wstring hex;
            std::wstring ascii;

            for (std::uint32_t j = 0; j < bytes_per_line && (i + j) < data_len; ++j) {
                const std::uint8_t value = data[i + j];

                if (!hex.empty())
                    hex += L' ';
                hex += std::format(L"{:02x}", value);

                ascii += (value >= ' ' && value <= '~') ? static_cast<wchar_t>(value) : L'.';
            }

            std::wcout << std::format(
                    L"  {: <{}}     {}{}", hex, hex_field_width, ascii, (i + bytes_per_line < data_len) ? L"\n" : L""
            );
        }
    }

    std::wcout << L"---------------------------" << std::endl;
}

std::unique_ptr<shared_loader_ctx> make_loader_ctx() {
    auto ctx = std::make_unique<shared_loader_ctx>();
    ctx->append_report_to_queue = append_report_to_queue;
    return ctx;
}

