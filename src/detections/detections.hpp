#ifndef DETECTIONS_HPP
#define DETECTIONS_HPP

#include <cstdint>
#include <winternl.h>
#include "../utils/window.hpp"

namespace detections {
  void validate_process(const SYSTEM_PROCESS_INFORMATION& process);
  void scan_loaded_modules();
  void scan_nvidia_overlay();
  void scan_medal_overlay();
  void validate_window(const utils::window_info& wi);
  void check_trust_provider_integrity();
} // namespace detections

#endif // DETECTIONS_HPP
