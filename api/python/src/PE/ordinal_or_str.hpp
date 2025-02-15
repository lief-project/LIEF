#pragma once

#include <nanobind/nanobind.h>
#include <string>

#include "LIEF/PE/resources/ResourceDialog.hpp"
#include "nanobind/extra/stl/u16string.h"

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)

template<>
struct type_caster<LIEF::PE::ResourceDialog::ordinal_or_str_t> {
  NB_TYPE_CASTER(LIEF::PE::ResourceDialog::ordinal_or_str_t, const_name("Optional[Union[int, str]]"));

  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(const LIEF::PE::ResourceDialog::ordinal_or_str_t& val,
                         rv_policy rp, cleanup_list *cl) noexcept
  {
    if (val.ordinal) {
      return int_(*val.ordinal).release();
    }

    if (val.string.empty()) {
      return none().release();
    }

    return type_caster<std::u16string>::from_cpp(val.string, rp, cl).inc_ref();
  }
};

NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)
