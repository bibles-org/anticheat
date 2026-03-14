#ifndef FILE_HPP
#define FILE_HPP
#include <cstdint>
#include <vector>
#include <string_view>

namespace utils {
    std::vector<std::uint8_t> read_file_contents(std::wstring_view path);
    bool touch_file(std::wstring_view path);
}

#endif //FILE_HPP
