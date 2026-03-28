#include <LIEF/config.h>

#if defined __cplusplus
  #include "spdlog/spdlog.h"
  #include <spdlog/fmt/fmt.h>
  #include <string>
  #include <set>
  #include <memory>
  #include <cstdint>
  #include <cstddef>
  #if LIEF_JSON_SUPPORT
    #ifndef LIEF_NLOHMANN_JSON_EXTERNAL
      #include "internal/nlohmann/json.hpp"
    #else
      #include <nlohmann/json.hpp>
    #endif
  #endif
#else
  #include <stdint.h>
  #include <stddef.h>
#endif
