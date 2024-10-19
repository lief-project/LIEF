#pragma once
#include "LIEF/DyldSharedCache/caching.hpp"

inline bool dsc_enable_cache() {
  return LIEF::dsc::enable_cache();
}

inline bool dsc_enable_cache_from_dir(std::string dir) {
  return LIEF::dsc::enable_cache(dir);
}
