#ifndef FILE_HPP
#define FILE_HPP
#include <cstdint>
#include <string_view>
#include <vector>

namespace utils {
  std::vector<std::uint8_t> read_file_contents(std::wstring_view path);
  bool touch_file(std::wstring_view path);

  std::size_t timestomp_and_get_file_size(std::wstring_view path);
} // namespace utils

#endif // FILE_HPP
