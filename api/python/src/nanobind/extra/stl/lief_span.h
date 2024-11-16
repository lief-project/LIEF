#pragma once

#include <nanobind/nanobind.h>
#include <string>

#include "LIEF/span.hpp"

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)

template<class T>
struct type_caster<LIEF::span<T>> {
  static_assert(std::is_same_v<uint8_t, std::remove_const_t<T>>,
                "Need uint8_t type");

  static constexpr auto IsRO = std::is_const_v<T>;

  NB_TYPE_CASTER(LIEF::span<T>, const_name("memoryview"));

  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
    return false;
  }

  static handle from_cpp(LIEF::span<T> val, rv_policy,
                         cleanup_list *) noexcept {
    static const uint8_t empty = 0;
    void* mem = (void*)val.data();
    if (val.empty()) {
      mem = (void*)&empty;
    }

    PyObject *ptr = PyMemoryView_FromMemory(
        reinterpret_cast<char *>(mem), val.size(), IsRO ? PyBUF_READ : PyBUF_WRITE);

    if (!ptr) {
      detail::fail("Could not allocate memoryview object!");
    }
    return ptr;
  }
};

NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)
