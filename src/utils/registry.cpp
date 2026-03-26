#include "registry.hpp"

namespace utils {
  std::wstring read_registry_string(HKEY hkey, std::wstring_view value_name) {
    DWORD size = 0;
    if (RegQueryValueExW(hkey, value_name.data(), nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS)
      return {};

    std::wstring result(size / sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(hkey, value_name.data(), nullptr, nullptr, reinterpret_cast<LPBYTE>(result.data()), &size) !=
        ERROR_SUCCESS)
      return {};

    while (!result.empty() && result.back() == L'\0')
      result.pop_back();

    return result;
  }

  bool enumerate_registry_content(
          HKEY hkey,
          const std::function<bool(DWORD type, std::wstring_view name, const std::vector<std::uint8_t>& data)>&
                  on_value_found,
          const std::function<bool(std::wstring_view name)>& on_subkey_found
  ) {

    DWORD num_subkeys = 0;
    DWORD num_values = 0;
    if (RegQueryInfoKeyW(
                hkey, nullptr, nullptr, nullptr, &num_subkeys, nullptr, nullptr, &num_values, nullptr, nullptr, nullptr,
                nullptr
        ) != ERROR_SUCCESS)
      return false;

    // enumerate subkeys
    if (on_subkey_found) {
      for (DWORD i = 0; i < num_subkeys; i++) {
        std::array<wchar_t, 0x3fff> name_buf{};
        auto name_len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hkey, i, name_buf.data(), &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
          continue;

        if (!on_subkey_found(std::wstring_view(name_buf.data(), name_len)))
          break;
      }
    }

    // enumerate values
    if (on_value_found) {
      for (DWORD i = 0; i < num_values; i++) {
        std::array<wchar_t, 0x3fff> name_buf{};
        auto name_len = static_cast<DWORD>(name_buf.size());
        DWORD type = 0;
        DWORD data_size = 0;

        RegEnumValueW(hkey, i, name_buf.data(), &name_len, nullptr, &type, nullptr, &data_size);

        std::vector<std::uint8_t> data(data_size);
        name_len = static_cast<DWORD>(name_buf.size());

        LSTATUS status = ERROR_MORE_DATA;
        for (int attempt = 0; attempt < 3 && status == ERROR_MORE_DATA; attempt++) {
          data.resize(data_size);
          data_size = static_cast<DWORD>(data.size());
          name_len = static_cast<DWORD>(name_buf.size());
          status = RegEnumValueW(hkey, i, name_buf.data(), &name_len, nullptr, &type, data.data(), &data_size);
        }

        if (status != ERROR_SUCCESS)
          continue;

        if (!on_value_found(type, std::wstring_view(name_buf.data(), name_len), data))
          break;
      }
    }

    return true;
  }
} // namespace utils
