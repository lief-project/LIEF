#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>

#include "binaryninja/binaryninjaapi.h"


// Bitfield support has been added in BinaryNinja 5.2 (Io)
#if BN_VERSION_MAJOR >= 5 && BN_VERSION_MINOR >= 2
  #define BN_BITFIELD_SUPPORT 1
#else
  #define BN_BITFIELD_SUPPORT 0
#endif

#if BN_VERSION_MAJOR >= 5 && BN_VERSION_MINOR >= 4
  #define BN_FRAGMENT_TYPE_CLASS_SUPPORT 1
#else
  #define BN_FRAGMENT_TYPE_CLASS_SUPPORT 0
#endif

// FunctionParameter switched from a flat `Variable location` to a `ValueLocation
// location` in BinaryNinja 5.4
#if BN_VERSION_MAJOR >= 5 && BN_VERSION_MINOR >= 4
  #define BN_VALUE_LOCATION_SUPPORT 1
#else
  #define BN_VALUE_LOCATION_SUPPORT 0
#endif


namespace binaryninja::api_compat {
namespace BN = BinaryNinja;

inline const BN::Type& get_type(const BN::Ref<BN::Type>& arg) {
  return *arg;
}

inline const BN::Type& get_type(const BN::Confidence<BN::Ref<BN::Type>>& arg) {
  return get_type(arg.GetValue());
}

inline bool as_bool(const BN::Ref<BN::Type>& arg) {
  return arg && arg != nullptr;
}

inline bool as_bool(const BN::Confidence<BN::Ref<BN::Type>>& arg) {
  return as_bool(arg.GetValue());
}

inline std::optional<int64_t>
    get_parameter_register(const BN::FunctionParameter& param, size_t idx) {
#if BN_VALUE_LOCATION_SUPPORT
  if (param.locationSource == BNValueLocationSource::DefaultLocationSource) {
    return std::nullopt;
  }
  std::optional<BN::Variable> var = param.location.GetVariableForParameter(idx);
  if (!var || var->type != BNVariableSourceType::RegisterVariableSourceType) {
    return std::nullopt;
  }
  return var->storage;
#else
  (void)idx;
  if (param.defaultLocation) {
    return std::nullopt;
  }
  if (param.location.type != BNVariableSourceType::RegisterVariableSourceType) {
    return std::nullopt;
  }
  return param.location.storage;
#endif
}


}
