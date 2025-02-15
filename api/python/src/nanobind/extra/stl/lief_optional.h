#pragma once

#include <nanobind/nanobind.h>
#include <string>

#include "LIEF/optional.hpp"

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)

template<class T>
struct type_caster<LIEF::optional<T>> {
  using Caster = make_caster<T>;
  NB_TYPE_CASTER(LIEF::optional<T>,
                 optional_name(Caster::Name));


  bool from_python(handle src, uint8_t flags, cleanup_list * cleanup) noexcept {
    if (src.is_none()) {
      value.reset();
      return true;
    }

    Caster caster;
    if (!caster.from_python(src, flags_for_local_caster<T>(flags), cleanup) ||
        !caster.template can_cast<T>())
        return false;

    value.emplace(caster.operator cast_t<T>());
    return true;
  }

  template <typename T_>
  static handle from_cpp(T_ &&value, rv_policy policy, cleanup_list *cleanup) noexcept
  {
    if (!value) {
      return none().release();
    }

    return Caster::from_cpp(forward_like_<T_>(*value), policy, cleanup);
  }
};

NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)
