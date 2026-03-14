#include "process.hpp"
#include <cstdint>

namespace utils {
    std::vector<SYSTEM_PROCESS_INFORMATION> capture_process_snapshot() {
        std::vector<std::uint8_t> buffer{};
        std::uint32_t size{};

        NTSTATUS status{};
        while ((status = NtQuerySystemInformation(
                        SystemProcessInformation, buffer.data(), static_cast<std::uint32_t>(buffer.size()),
                        reinterpret_cast<ULONG*>(&size)
                )) == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            buffer.resize(size);
                }

        std::vector<SYSTEM_PROCESS_INFORMATION> process_snapshot{};
        auto process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                buffer.data() + reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data())->NextEntryOffset
        );
        while (process->NextEntryOffset) {
            process_snapshot.emplace_back(*process);
            process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<std::uint8_t*>(process) + process->NextEntryOffset
            );
        }
        return process_snapshot;
    }
}