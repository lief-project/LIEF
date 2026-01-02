#pragma once
#include "binaryninja/binaryninjaapi.h"


// Bitfield support has been added in BinaryNinja 5.2 (Io)
#if BN_VERSION_MAJOR >= 5 && BN_VERSION_MINOR >= 2
#define BN_BITFIELD_SUPPORT 1
#else
#define BN_BITFIELD_SUPPORT 0
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


}
