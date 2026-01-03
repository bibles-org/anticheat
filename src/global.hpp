#ifndef GLOBAL_HPP
#define GLOBAL_HPP
#include <memory>
#include "../loader/shared_ctx.hpp"

std::unique_ptr<shared_loader_ctx> g_loader_ctx;
#endif //GLOBAL_HPP
