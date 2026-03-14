#include "file.hpp"
#include <cstring>
#include <experimental/scope>
#include <windows.h>

namespace utils {
    std::vector<std::uint8_t> read_file_contents(std::wstring_view path) {
        std::vector<std::uint8_t> buf;

        if (path.empty())
            return buf;

        const HANDLE file = CreateFileW(
                path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
        );
        if (file == INVALID_HANDLE_VALUE)
            return buf;

        std::experimental::scope_exit file_guard([&] {
            CloseHandle(file);
        });

        DWORD file_size = GetFileSize(file, nullptr);
        if (!file_size)
            return buf;

        buf.resize(file_size);
        DWORD bytes_read = 0;

        if (ReadFile(file, buf.data(), file_size, &bytes_read, nullptr) && bytes_read) {
            if (bytes_read < file_size) {
                std::memset(buf.data() + bytes_read, 0, file_size - bytes_read);
                buf.resize(bytes_read);
            }
        } else {
            std::memset(buf.data(), 0, buf.size());
            buf.clear();
        }

        return buf;
    }

    bool touch_file(std::wstring_view path) {
        HANDLE file = CreateFileW(
            path.data(),
            FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (file == INVALID_HANDLE_VALUE)
            return false;

        constexpr FILETIME last_access = { 0xFFFFFFFF, 0xFFFFFFFF };
        const bool result = SetFileTime(file, nullptr, &last_access, nullptr);
        CloseHandle(file);
        return result;
    }
} // namespace utils
