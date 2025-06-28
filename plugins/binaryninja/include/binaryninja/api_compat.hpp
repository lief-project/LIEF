#pragma once
#include "binaryninja/binaryninjaapi.h"
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
