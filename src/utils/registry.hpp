#ifndef REGISTRY_HPP
#define REGISTRY_HPP
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <windows.h>
namespace utils {
  std::wstring read_registry_string(HKEY hkey, std::wstring_view value_name);

  bool enumerate_registry_content(
          HKEY hkey,
          const std::function<bool(DWORD type, std::wstring_view name, const std::vector<std::uint8_t>& data)>&
                  on_value_found,
          const std::function<bool(std::wstring_view name)>& on_subkey_found = nullptr
  );
} // namespace utils
#endif // REGISTRY_HPP
