#include "loader/shared_ctx.hpp"
#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE,
    DWORD fdwReason,
    std::unique_ptr<shared_loader_ctx> loader_ctx);

int main() {
    // manual map the anticheat dll and call its entrypoint
    DllMain(nullptr, 0, make_loader_ctx());
}