#ifndef MAIN_CLASS_HPP
#define MAIN_CLASS_HPP
#include <winternl.h>

class vac_ctx {
  LARGE_INTEGER counter_freq{};
  LARGE_INTEGER begin_time{};
  LARGE_INTEGER end_time{};
  HWND dagor_window_handle{};

  public:
  vac_ctx();
  virtual ~vac_ctx();

  virtual bool on_process_attach();
  virtual bool on_thread_attach();
};

#endif // MAIN_CLASS_HPP
