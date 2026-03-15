#include "registry.hpp"

namespace utils {
    std::wstring read_registry_string(const HKEY hkey, std::wstring_view value_name) {
        DWORD size = 0;
        if (RegQueryValueExW(hkey, value_name.data(), nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS)
            return {};

        std::wstring result(size / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(
                    hkey, value_name.data(), nullptr, nullptr, reinterpret_cast<LPBYTE>(result.data()), &size
            ) != ERROR_SUCCESS)
            return {};

        while (!result.empty() && result.back() == L'\0')
            result.pop_back();

        return result;
    }
} // namespace utils
