
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
#include "PE/pyPE.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<LoadConfigurationV1>(nb::module_& m) {
  nb::class_<LoadConfigurationV1, LoadConfigurationV0> Config(m, "LoadConfigurationV1",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV0` enhanced with *Control Flow Guard*.
      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN_8_1`
      )delim"_doc);


  #define ENTRY(X) .value(to_string(LoadConfigurationV1::IMAGE_GUARD::X), LoadConfigurationV1::IMAGE_GUARD::X)
  enum_<LoadConfigurationV1::IMAGE_GUARD>(Config, "IMAGE_GUARD", nb::is_arithmetic())
    ENTRY(NONE)
    ENTRY(CF_INSTRUMENTED)
    ENTRY(CFW_INSTRUMENTED)
    ENTRY(CF_FUNCTION_TABLE_PRESENT)
    ENTRY(SECURITY_COOKIE_UNUSED)
    ENTRY(PROTECT_DELAYLOAD_IAT)
    ENTRY(DELAYLOAD_IAT_IN_ITS_OWN_SECTION)
    ENTRY(CF_EXPORT_SUPPRESSION_INFO_PRESENT)
    ENTRY(CF_ENABLE_EXPORT_SUPPRESSION)
    ENTRY(CF_LONGJUMP_TABLE_PRESENT)
    ENTRY(RF_INSTRUMENTED)
    ENTRY(RF_ENABLE)
    ENTRY(RF_STRICT)
    ENTRY(RETPOLINE_PRESENT)
    ENTRY(EH_CONTINUATION_TABLE_PRESENT)
  ;
  #undef ENTRY

  Config
    .def(nb::init<>())

    .def_prop_rw("guard_cf_check_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV1::guard_cf_check_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV1::guard_cf_check_function_pointer),
        "The VA where Control Flow Guard check-function pointer is stored."_doc)

    .def_prop_rw("guard_cf_dispatch_function_pointer",
        nb::overload_cast<>(&LoadConfigurationV1::guard_cf_dispatch_function_pointer, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV1::guard_cf_dispatch_function_pointer),
        "The VA where Control Flow Guard dispatch-function pointer is stored."_doc)

    .def_prop_rw("guard_cf_function_table",
        nb::overload_cast<>(&LoadConfigurationV1::guard_cf_function_table, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV1::guard_cf_function_table),
        "The VA of the sorted table of RVAs of each Control Flow Guard function in the image."_doc)

    .def_prop_rw("guard_cf_function_count",
        nb::overload_cast<>(&LoadConfigurationV1::guard_cf_function_count, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfigurationV1::guard_cf_function_count),
        "The count of unique RVAs in the :attr:`~lief.PE.LoadConfigurationV1.guard_cf_function_table`"_doc)

    .def_prop_rw("guard_flags",
        nb::overload_cast<>(&LoadConfigurationV1::guard_flags, nb::const_),
        nb::overload_cast<LoadConfigurationV1::IMAGE_GUARD>(&LoadConfigurationV1::guard_flags),
        "Control Flow Guard related flags."_doc)

    .def("has",
        nb::overload_cast<LoadConfigurationV1::IMAGE_GUARD>(&LoadConfigurationV1::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.PE.GUARD_CF_FLAGS) " is present in "
        ":attr:`~lief.PE.LoadConfigurationV1.guard_flags`"_doc,
        "flag"_a)

    .def_prop_ro("guard_cf_flags_list",
        &LoadConfigurationV1::guard_cf_flags_list,
        "Return list of " RST_CLASS_REF(lief.PE.GUARD_CF_FLAGS) " present in "
        ":attr:`~lief.PE.LoadConfigurationV1.guard_flags`"_doc,
        nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<LoadConfigurationV1::IMAGE_GUARD>(&LoadConfigurationV1::has, nb::const_))

    LIEF_COPYABLE(LoadConfigurationV1)
    LIEF_DEFAULT_STR(LoadConfigurationV1);
}

}
