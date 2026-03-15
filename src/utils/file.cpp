#include "file.hpp"
#include <experimental/scope>
#include <windows.h>

namespace utils {
    std::vector<std::uint8_t> read_file_contents(std::wstring_view path) {
        if (path.empty())
            return {};

        const HANDLE file = CreateFileW(
                path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
        );
        if (file == INVALID_HANDLE_VALUE)
            return {};

        std::experimental::scope_exit file_guard([&] {
            CloseHandle(file);
        });

        const DWORD file_size = GetFileSize(file, nullptr);
        if (!file_size)
            return {};

        std::vector<std::uint8_t> buf(file_size);
        DWORD bytes_read = 0;

        if (!ReadFile(file, buf.data(), file_size, &bytes_read, nullptr) || !bytes_read) {
            return {};
        }

        if (bytes_read < file_size) {
            buf.resize(bytes_read);
        }

        return buf;
    }

    // this function probably was meant to freeze the last access time of the file
    // and if that is the case, it is only applied to the temporary handle
    // that is being used here to do literally nothing, which defeats the purpose..
    bool touch_file(std::wstring_view path) {
        const HANDLE file = CreateFileW(
                path.data(), GENERIC_READ | FILE_WRITE_ATTRIBUTES, FILE_SHARE_VALID_FLAGS, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr
        );
        if (file == INVALID_HANDLE_VALUE)
            return false;

        std::experimental::scope_exit file_guard([&] {
            CloseHandle(file);
        });

        constexpr FILETIME last_access = {0xFFFFFFFF, 0xFFFFFFFF};
        const bool result = SetFileTime(file, nullptr, &last_access, nullptr);
        return result;
    }

    std::size_t timestomp_and_get_file_size(std::wstring_view path) {
        const HANDLE file = CreateFileW(
                path.data(), GENERIC_READ | FILE_WRITE_ATTRIBUTES, FILE_SHARE_VALID_FLAGS, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr
        );
        if (file == INVALID_HANDLE_VALUE)
            return false;

        std::experimental::scope_exit file_guard([&] {
            CloseHandle(file);
        });

        constexpr FILETIME last_access = {0xFFFFFFFF, 0xFFFFFFFF};
        if (!SetFileTime(file, nullptr, &last_access, nullptr))
            return 0;

        LARGE_INTEGER file_size = {};
        if (!GetFileSizeEx(file, &file_size))
            return 0;

        return static_cast<std::size_t>(file_size.QuadPart);
    }
} // namespace utils
