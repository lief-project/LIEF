#pragma once

#include <nanobind/nanobind.h>
#include <string>

#include "LIEF/errors.hpp"

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)

template<class T>
struct type_caster<LIEF::result<T>> {
  using Caster = make_caster<T>;
  using ErrCaster = make_caster<lief_errors>;
  NB_TYPE_CASTER(LIEF::result<T>,
                const_name("Union[") + Caster::Name + const_name(",") + const_name("lief.lief_errors") + const_name("]"));


  bool from_python(handle src, uint8_t flags, cleanup_list * cleanup) noexcept {
    Caster caster;
    if (!caster.from_python(src, flags_for_local_caster<T>(flags), cleanup) ||
        !caster.template can_cast<T>())
    {
      ErrCaster err_caster;
      if (!err_caster.from_python(src, flags_for_local_caster<lief_errors>(flags), cleanup) ||
          !err_caster.template can_cast<lief_errors>())
      {
        value.emplace(err_caster.operator cast_t<lief_errors>());
        return true;
      }
      return false;
    }

    value.emplace(caster.operator cast_t<T>());
    return true;
  }

  template <typename T_>
  static handle from_cpp(T_ &&value, rv_policy policy, cleanup_list *cleanup) noexcept
  {
    if (value) {
      return Caster::from_cpp(forward_like_<T_>(*value), policy, cleanup);
    }

    return ErrCaster::from_cpp(forward_like_<T_>(get_error(value)), policy, cleanup);
  }
};

NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)
