#ifndef REGISTRY_HPP
#define REGISTRY_HPP
#include <windows.h>
#include <string>
namespace utils {
    std::wstring read_registry_string(const HKEY hkey, std::wstring_view value_name);
}
#endif //REGISTRY_HPP
