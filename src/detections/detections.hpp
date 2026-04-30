#ifndef DETECTIONS_HPP
#define DETECTIONS_HPP

#include <vector>
#include "../utils/module.hpp"
#include "../utils/window.hpp"

namespace detections {
  void validate_processes(const std::vector<utils::process_info>& processes);
  void validate_windows(const std::vector<utils::window_info>& windows);
  void validate_modules(const std::vector<utils::module_info>& modules);
  void check_present_hook(const std::vector<utils::module_info>& modules);
  void check_sip_hijack_and_appinit_injection();

  //void scan_shimcache_execution_history();
  //void scan_compat_assistant_execution_history();
} // namespace detections

#endif // DETECTIONS_HPP
