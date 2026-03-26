#ifndef STRING_HPP
#define STRING_HPP
#include <string_view>

namespace utils {
  bool str_icontains(std::string_view str, std::string_view substr);
  bool str_icontains(std::wstring_view str, std::wstring_view substr);
  bool str_iequals(std::string_view lhs, std::string_view rhs);
  bool str_iequals(std::wstring_view lhs, std::wstring_view rhs);

  std::string wide_to_utf8(std::wstring_view wide);
  std::wstring utf8_to_wide(std::string_view utf8);
} // namespace utils


#endif // STRING_HPP
