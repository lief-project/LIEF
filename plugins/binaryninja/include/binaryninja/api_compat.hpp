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
namespace bn = BinaryNinja;

inline const bn::Type& get_type(const bn::Ref<bn::Type>& arg) {
  return *arg;
}

inline const bn::Type& get_type(const bn::Confidence<bn::Ref<bn::Type>>& arg) {
  return get_type(arg.GetValue());
}

inline bool as_bool(const bn::Ref<bn::Type>& arg) {
  return arg && arg != nullptr;
}

inline bool as_bool(const bn::Confidence<bn::Ref<bn::Type>>& arg) {
  return as_bool(arg.GetValue());
}

inline std::optional<int64_t>
    get_parameter_register(const bn::FunctionParameter& param, size_t idx) {
#if BN_VALUE_LOCATION_SUPPORT
  if (param.locationSource == BNValueLocationSource::DefaultLocationSource) {
    return std::nullopt;
  }
  std::optional<bn::Variable> var = param.location.GetVariableForParameter(idx);
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
