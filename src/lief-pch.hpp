// IWYU pragma: begin_exports
#include "LIEF/config.h"

#if defined __cplusplus
  #include "spdlog/spdlog.h"
  #include <spdlog/fmt/fmt.h>
  #include <spdlog/fmt/ranges.h>

  #include <unordered_map>
  #include <algorithm>
  #include <array>
  #include <cstddef>
  #include <cstdint>
  #include <map>
  #include <memory>
  #include <ostream>
  #include <set>
  #include <sstream>
  #include <string>
  #include <vector>

  #if LIEF_JSON_SUPPORT
    #if defined(__clang__)
      #pragma clang diagnostic push
      #pragma clang diagnostic ignored "-Wunknown-warning-option"
      #pragma clang diagnostic ignored "-Wlifetime-safety"
    #endif
    #ifndef LIEF_NLOHMANN_JSON_EXTERNAL
      #include "internal/nlohmann/json.hpp"
    #else
      #include <nlohmann/json.hpp>
    #endif
    #if defined(__clang__)
      #pragma clang diagnostic pop
    #endif
  #endif
#else
  #include <stddef.h>
  #include <stdint.h>
#endif
// IWYU pragma: end_exports
