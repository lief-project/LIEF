/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <algorithm>

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "LIEF/MachO/ChainedPointerAnalysis.hpp"

#include "MachO/pyMachO.hpp"
#include "typing.hpp"

namespace LIEF::MachO::py {

struct ChainedPointer : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(ChainedPointer, nanobind::object);

  NB_OBJECT_DEFAULT(ChainedPointer, object,
      "Union["
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_rebase_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_bind_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_rebase_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_bind_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_64_rebase_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_bind24_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_arm64e_auth_bind24_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_64_bind_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_64_kernel_cache_rebase_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_rebase_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_bind_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_cache_rebase_t, "
      "lief.MachO.ChainedPointerAnalysis.dyld_chained_ptr_32_firmware_rebase_t, "
      "int, "
      "None"
      "]",
      check)

  static bool check(handle h) {
    return true;
  }
};

template<>
void create<ChainedPointerAnalysis>(nb::module_& m) {
  nb::class_<ChainedPointerAnalysis> clazz(m, "ChainedPointerAnalysis");
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t>(
    clazz, "dyld_chained_ptr_arm64e_rebase_t"
  )
    .def_prop_ro("unpack_target",
        &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t::unpack_target)

    .def_prop_ro("target",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("high8",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t& ptr) {
        return (uint64_t)ptr.high8;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    .def_prop_ro("auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t& ptr) {
        return (bool)ptr.auth;
      }
    )

    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t>(
    clazz, "dyld_chained_ptr_arm64e_bind_t"
  )
    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& ptr) {
        return (uint64_t)ptr.ordinal;
      }
    )
    .def_prop_ro("zero",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& ptr) {
        return (uint64_t)ptr.zero;
      }
    )
    .def_prop_ro("addend",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& ptr) {
        return (uint64_t)ptr.addend;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    .def_prop_ro("auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& ptr) {
        return (bool)ptr.auth;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t>(
    clazz, "dyld_chained_ptr_arm64e_auth_rebase_t"
  )
    .def_prop_ro("target",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("diversity",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (uint64_t)ptr.diversity;
      }
    )
    .def_prop_ro("addr_div",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (uint64_t)ptr.addr_div;
      }
    )
    .def_prop_ro("key",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (uint64_t)ptr.key;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    .def_prop_ro("auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& ptr) {
        return (uint64_t)ptr.auth;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t>(
    clazz, "dyld_chained_ptr_arm64e_auth_bind_t")

    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (uint64_t)ptr.ordinal;
      }
    )
    .def_prop_ro("zero",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (uint64_t)ptr.zero;
      }
    )
    .def_prop_ro("diversity",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (uint64_t)ptr.diversity;
      }
    )
    .def_prop_ro("addr_div",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (uint64_t)ptr.addr_div;
      }
    )
    .def_prop_ro("key",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (uint64_t)ptr.key;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    .def_prop_ro("auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& ptr) {
        return (bool)ptr.auth;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t>(
    clazz, "dyld_chained_ptr_64_rebase_t"
  )

    .def_prop_ro("unpack_target",
        &ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t::unpack_target)

    .def_prop_ro("target",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("high8",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t& ptr) {
        return (uint64_t)ptr.high8;
      }
    )
    .def_prop_ro("reserved",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t& ptr) {
        return (uint64_t)ptr.reserved;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t>(
    clazz, "dyld_chained_ptr_arm64e_bind24_t"
  )
    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& ptr) {
        return (uint64_t)ptr.ordinal;
      }
    )
    .def_prop_ro("zero",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& ptr) {
        return (uint64_t)ptr.zero;
      }
    )
    .def_prop_ro("addend",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& ptr) {
        return (uint64_t)ptr.addend;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    .def_prop_ro("auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& ptr) {
        return (bool)ptr.auth;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t>(
    clazz, "dyld_chained_ptr_arm64e_auth_bind24_t"
  )
    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (uint64_t)ptr.ordinal;
      }
    )
    .def_prop_ro("zero",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (uint64_t)ptr.zero;
      }
    )
    .def_prop_ro("diversity",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (uint64_t)ptr.diversity;
      }
    )
    .def_prop_ro("addr_div",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (uint64_t)ptr.addr_div;
      }
    )
    .def_prop_ro("key",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (uint64_t)ptr.key;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    .def_prop_ro("auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& ptr) {
        return (bool)ptr.auth;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t>(
    clazz, "dyld_chained_ptr_64_bind_t"
  )
    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t& ptr) {
        return (uint64_t)ptr.ordinal;
      }
    )
    .def_prop_ro("addend",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t& ptr) {
        return (uint64_t)ptr.addend;
      }
    )
    .def_prop_ro("reserved",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t& ptr) {
        return (uint64_t)ptr.reserved;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t>(
    clazz, "dyld_chained_ptr_64_kernel_cache_rebase_t"
  )
    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("cache_level",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (uint64_t)ptr.cache_level;
      }
    )
    .def_prop_ro("diversity",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (uint64_t)ptr.diversity;
      }
    )
    .def_prop_ro("addr_div",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (uint64_t)ptr.addr_div;
      }
    )
    .def_prop_ro("key",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (uint64_t)ptr.key;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("is_auth",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& ptr) {
        return (bool)ptr.is_auth;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_32_rebase_t>(
    clazz, "dyld_chained_ptr_32_rebase_t"
  )
    .def_prop_ro("target",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_rebase_t& ptr) {
        return (uint64_t)ptr.bind;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_32_rebase_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t>(
    clazz, "dyld_chained_ptr_32_bind_t"
  )
    .def_prop_ro("ordinal",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t& ptr) {
        return (uint64_t)ptr.ordinal;
      }
    )
    .def_prop_ro("addend",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t& ptr) {
        return (uint64_t)ptr.addend;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    .def_prop_ro("bind",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t& ptr) {
        return (bool)ptr.bind;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_32_cache_rebase_t>(
    clazz, "dyld_chained_ptr_32_cache_rebase_t"
  )
    .def_prop_ro("target",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_cache_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_cache_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_32_cache_rebase_t);
  ;
  nb::class_<ChainedPointerAnalysis::dyld_chained_ptr_32_firmware_rebase_t>(
    clazz, "dyld_chained_ptr_32_firmware_rebase_t"
  )
    .def_prop_ro("target",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_firmware_rebase_t& ptr) {
        return (uint64_t)ptr.target;
      }
    )
    .def_prop_ro("next",
      [] (const ChainedPointerAnalysis::dyld_chained_ptr_32_firmware_rebase_t& ptr) {
        return (uint64_t)ptr.next;
      }
    )
    LIEF_DEFAULT_STR(ChainedPointerAnalysis::dyld_chained_ptr_32_firmware_rebase_t);
  ;
  clazz
    .def_static("stride",
                &ChainedPointerAnalysis::stride, "fmt"_a)
    .def_static("from_value",
                &ChainedPointerAnalysis::from_value, "ptr"_a, "size"_a)
    .def_prop_ro("value",
                  &ChainedPointerAnalysis::value)
    .def_prop_ro("size",
                  &ChainedPointerAnalysis::size)
    .def_prop_ro("dyld_chained_ptr_arm64e_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase)
    .def_prop_ro("dyld_chained_ptr_arm64e_bind",
                  &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind)
    .def_prop_ro("dyld_chained_ptr_arm64e_auth_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase)
    .def_prop_ro("dyld_chained_ptr_arm64e_auth_bind",
                  &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind)
    .def_prop_ro("dyld_chained_ptr_64_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_64_rebase)
    .def_prop_ro("dyld_chained_ptr_arm64e_bind24",
                  &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24)
    .def_prop_ro("dyld_chained_ptr_arm64e_auth_bind24",
                  &ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24)
    .def_prop_ro("dyld_chained_ptr_64_bind",
                  &ChainedPointerAnalysis::dyld_chained_ptr_64_bind)
    .def_prop_ro("dyld_chained_ptr_64_kernel_cache_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase)
    .def_prop_ro("dyld_chained_ptr_32_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_32_rebase)
    .def_prop_ro("dyld_chained_ptr_32_bind",
                  &ChainedPointerAnalysis::dyld_chained_ptr_32_bind)
    .def_prop_ro("dyld_chained_ptr_32_cache_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_32_cache_rebase)
    .def_prop_ro("dyld_chained_ptr_32_firmware_rebase",
                  &ChainedPointerAnalysis::dyld_chained_ptr_32_firmware_rebase)
    .def("get_as",
      [] (const ChainedPointerAnalysis& self, DYLD_CHAINED_PTR_FORMAT fmt) -> ChainedPointer {
         ChainedPointerAnalysis::union_pointer_t ptr = self.get_as(fmt);
         switch (ptr.type) {
          case ChainedPointerAnalysis::PTR_TYPE::UNKNOWN:
            return nb::cast(ptr.raw);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_ARM64E_REBASE:
            return nb::cast(ptr.arm64e_rebase);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_ARM64E_BIND:
            return nb::cast(ptr.arm64e_bind);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_ARM64E_AUTH_REBASE:
            return nb::cast(ptr.arm64e_auth_rebase);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_ARM64E_AUTH_BIND:
            return nb::cast(ptr.arm64e_auth_bind);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_64_REBASE:
            return nb::cast(ptr.ptr_64_rebase);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_ARM64E_BIND24:
            return nb::cast(ptr.arm64e_bind24);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_ARM64E_AUTH_BIND24:
            return nb::cast(ptr.arm64e_auth_bind24);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_64_BIND:
            return nb::cast(ptr.ptr_64_bind);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_64_KERNEL_CACHE_REBASE:
            return nb::cast(ptr.ptr_64_kernel_cache_rebase);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_32_REBASE:
            return nb::cast(ptr.ptr_32_rebase);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_32_BIND:
            return nb::cast(ptr.ptr_32_bind);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_32_CACHE_REBASE:
            return nb::cast(ptr.ptr_32_cache_rebase);

          case ChainedPointerAnalysis::PTR_TYPE::DYLD_CHAINED_PTR_32_FIRMWARE_REBASE:
            return nb::cast(ptr.ptr_32_firmware_rebase);
         }
         return nb::none();
      }
    )
  ;

}
}
