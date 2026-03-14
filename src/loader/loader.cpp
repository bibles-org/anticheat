#include "loader.hpp"
#include <format>
#include <string>
#include <iostream>
#include <utility>

namespace loader {
    void append_report(
            message_id id, const char* str1, std::uint32_t str1_len, const char* str2, std::uint32_t str2_len,
            std::uint8_t* data, std::uint32_t data_len
    ) {
        std::cout << std::format("[{:#x}]:\n", std::to_underlying(id));

        if (str1) {
            const std::string_view str1_view{str1, static_cast<size_t>(str1_len)};
            std::cout << std::format("  1-'{}'\n", str1_view);
        }
        if (str2) {
            const std::string_view str2_view{str2, static_cast<size_t>(str2_len)};
            std::cout << std::format("  2-'{}'\n", str2_view);
        }

        if (data) {
            constexpr int bytes_per_line = 8;
            constexpr int hex_field_width = bytes_per_line * 2 + (bytes_per_line - 1); // 23

            for (std::uint32_t i = 0; i < data_len; i += bytes_per_line) {
                std::string hex;
                std::string ascii;

                for (std::uint32_t j = 0; j < bytes_per_line && (i + j) < data_len; ++j) {
                    const std::uint8_t value = data[i + j];

                    if (!hex.empty())
                        hex += ' ';
                    hex += std::format("{:02x}", value);

                    ascii += (value >= ' ' && value <= '~') ? static_cast<char>(value) : '.';
                }

                std::cout << std::format(
                        "  {: <{}}     {}{}", hex, hex_field_width, ascii, (i + bytes_per_line < data_len) ? "\n" : ""
                );
            }
        }

        std::cout << "---------------------------" << std::endl;
    }
}