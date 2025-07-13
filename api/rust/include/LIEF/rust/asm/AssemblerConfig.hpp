#pragma once
#include "LIEF/visibility.h"
#include <memory>
#include "LIEF/asm/AssemblerConfig.hpp"

struct AssemblerConfig_r;

LIEF_API std::unique_ptr<LIEF::assembly::AssemblerConfig>
  from_rust(const AssemblerConfig_r& config);
