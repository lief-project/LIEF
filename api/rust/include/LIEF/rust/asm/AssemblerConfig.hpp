#pragma once
#include "LIEF/asm/AssemblerConfig.hpp"
#include "LIEF/visibility.h"
#include <memory>

struct AssemblerConfig_r;

LIEF_API std::unique_ptr<LIEF::assembly::AssemblerConfig>
    from_rust(const AssemblerConfig_r& config);
