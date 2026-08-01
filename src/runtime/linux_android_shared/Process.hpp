#pragma once
#include <optional>
#include <string>

namespace LIEF::runtime::linux_android {
std::optional<std::string> cmdline();
}
