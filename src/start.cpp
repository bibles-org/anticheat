#include <windows.h>
#include "global.hpp"

BOOL WINAPI DllMain(
    HINSTANCE,
    DWORD fdwReason,
    std::unique_ptr<shared_loader_ctx> loader_ctx) {
    g_loader_ctx = std::move(loader_ctx);


}
