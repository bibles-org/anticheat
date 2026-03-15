#include "string.hpp"
#include <algorithm>
#include <cwctype>
#include <ranges>
#include <windows.h>

namespace utils {
  bool str_icontains(std::string_view str, std::string_view substr) {
    return std::ranges::search(str, substr, [](const char a, const char b) {
             return std::tolower(a) == std::tolower(b);
           }).begin() != str.end();
  }

  bool str_icontains(std::wstring_view str, std::wstring_view substr) {
    return std::ranges::search(str, substr, [](const wchar_t a, const wchar_t b) {
             return std::towlower(a) == std::towlower(b);
           }).begin() != str.end();
  }

  bool str_iequals(std::string_view lhs, std::string_view rhs) {
    return std::ranges::equal(lhs, rhs, [](const char a, const char b) {
      return std::tolower(a) == std::tolower(b);
    });
  }

  bool str_iequals(std::wstring_view lhs, std::wstring_view rhs) {
    return std::ranges::equal(lhs, rhs, [](const wchar_t a, const wchar_t b) {
      return std::towlower(a) == std::towlower(b);
    });
  }


  std::string wide_to_utf8(std::wstring_view wide) {
    if (wide.empty())
      return {};

    const int size =
            WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0)
      return {};

    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), result.data(), size, nullptr, nullptr);
    return result;
  }

  std::wstring utf8_to_wide(std::string_view utf8) {
    if (utf8.empty())
      return {};

    const int size = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (size <= 0)
      return {};

    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), result.data(), size);
    return result;
  }
} // namespace utils
