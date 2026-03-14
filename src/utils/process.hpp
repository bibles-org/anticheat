#ifndef PROCESS_HPP
#define PROCESS_HPP

#include <winternl.h>
#include <vector>
namespace utils {
    std::vector<SYSTEM_PROCESS_INFORMATION> capture_process_snapshot();
}

#endif //PROCESS_HPP
