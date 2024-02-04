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

#include "LIEF/PE/LoadConfigurations.hpp"
#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<LoadConfiguration>(nb::module_& m) {
  nb::class_<LoadConfiguration, LIEF::Object> Config(m, "LoadConfiguration",
    R"delim(
    Class that represents the default PE's ``LoadConfiguration``
    It's the base class for any future versions of the structure
    )delim"_doc);

  #define ENTRY(X) .value(to_string(LoadConfiguration::VERSION::X), LoadConfiguration::VERSION::X)
  enum_<LoadConfiguration::VERSION>(Config, "VERSION")
    ENTRY(UNKNOWN)
    ENTRY(SEH)
    ENTRY(WIN_8_1)
    ENTRY(WIN_10_0_9879)
    ENTRY(WIN_10_0_14286)
    ENTRY(WIN_10_0_14383)
    ENTRY(WIN_10_0_14901)
    ENTRY(WIN_10_0_15002)
    ENTRY(WIN_10_0_16237)
    ENTRY(WIN_10_0_18362)
    ENTRY(WIN_10_0_19534)
    ENTRY(WIN_10_0_MSVC_2019)
    ENTRY(WIN_10_0_MSVC_2019_16)
  ;
  #undef ENTRY

  Config
    .def(nb::init<>())

    .def_prop_ro("version",
        &LoadConfiguration::version,
        "(SDK) Version of the structure. (" RST_CLASS_REF(lief.PE.WIN_VERSION) ")"_doc)

    .def_prop_rw("characteristics",
        nb::overload_cast<>(&LoadConfiguration::characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::characteristics),
        "Characteristics of the structure."_doc)

    .def_prop_ro("size",
        nb::overload_cast<>(&LoadConfiguration::size, nb::const_),
        "Size of the structure which is an alias for " RST_ATTR_REF(lief.PE.LoadConfiguration.characteristics) ""_doc)

    .def_prop_rw("timedatestamp",
        nb::overload_cast<>(&LoadConfiguration::timedatestamp, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::timedatestamp),
        "Date and time stamp value"_doc)

    .def_prop_rw("major_version",
        nb::overload_cast<>(&LoadConfiguration::major_version, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfiguration::major_version),
        "Major Version"_doc)

    .def_prop_rw("minor_version",
        nb::overload_cast<>(&LoadConfiguration::minor_version, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfiguration::minor_version),
        "Minor version"_doc)

    .def_prop_rw("global_flags_clear",
        nb::overload_cast<>(&LoadConfiguration::global_flags_clear, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::global_flags_clear),
        "The global loader flags to clear for this process as the loader start the process."_doc)

    .def_prop_rw("global_flags_set",
        nb::overload_cast<>(&LoadConfiguration::global_flags_set, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::global_flags_set),
        "The global loader flags to set for this process as the loader starts the process."_doc)

    .def_prop_rw("critical_section_default_timeout",
        nb::overload_cast<>(&LoadConfiguration::critical_section_default_timeout, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::critical_section_default_timeout),
        "The default timeout value to use for is process’s critical sections that are abandoned."_doc)

    .def_prop_rw("decommit_free_block_threshold",
        nb::overload_cast<>(&LoadConfiguration::decommit_free_block_threshold, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfiguration::decommit_free_block_threshold),
        "Memory that must be freed before it is returned to the system, in bytes."_doc)

    .def_prop_rw("decommit_total_free_threshold",
        nb::overload_cast<>(&LoadConfiguration::decommit_total_free_threshold, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfiguration::decommit_total_free_threshold),
        "Total amount of free memory, in bytes"_doc)

    .def_prop_rw("lock_prefix_table",
        nb::overload_cast<>(&LoadConfiguration::lock_prefix_table, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfiguration::lock_prefix_table),
        "The **VA** of a list of addresses where the ``LOCK`` prefix "
        "is used so that they can be replaced with ``NOP`` on single processor machines."_doc)

    .def_prop_rw("maximum_allocation_size",
        nb::overload_cast<>(&LoadConfiguration::maximum_allocation_size, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfiguration::maximum_allocation_size),
        "Maximum allocation size, in bytes."_doc)

    .def_prop_rw("virtual_memory_threshold",
        nb::overload_cast<>(&LoadConfiguration::virtual_memory_threshold, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfiguration::virtual_memory_threshold),
        "Maximum virtual memory size, in bytes."_doc)

    .def_prop_rw("process_affinity_mask",
        nb::overload_cast<>(&LoadConfiguration::process_affinity_mask, nb::const_),
        nb::overload_cast<uint64_t>(&LoadConfiguration::process_affinity_mask),
        "Setting this field to a non-zero value is equivalent to calling "
        "``SetProcessAffinityMask`` with this value during process startup (.exe only)"_doc)

    .def_prop_rw("process_heap_flags",
        nb::overload_cast<>(&LoadConfiguration::process_heap_flags, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::process_heap_flags),
        R"delim(
        Process heap flags that correspond to the first argument of the ``HeapCreate``
        function. These flags apply to the process heap that is created during process startup.
        )delim"_doc)

    .def_prop_rw("csd_version",
        nb::overload_cast<>(&LoadConfiguration::csd_version, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfiguration::csd_version),
        "The service pack version identifier."_doc)

    .def_prop_rw("reserved1",
        nb::overload_cast<>(&LoadConfiguration::reserved1, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfiguration::reserved1),
        "Must be zero."_doc)

    .def_prop_rw("dependent_load_flags",
        nb::overload_cast<>(&LoadConfiguration::dependent_load_flags, nb::const_),
        nb::overload_cast<uint16_t>(&LoadConfiguration::dependent_load_flags),
        "On recent the version of the structure, Microsoft renamed reserved1 to DependentLoadFlags. "
        "This is an alias for " RST_ATTR_REF(lief.PE.LoadConfiguration.reserved1) ""_doc)

    .def_prop_rw("editlist",
        nb::overload_cast<>(&LoadConfiguration::editlist, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::editlist),
        "Reserved for use by the system."_doc)

    .def_prop_rw("security_cookie",
        nb::overload_cast<>(&LoadConfiguration::security_cookie, nb::const_),
        nb::overload_cast<uint32_t>(&LoadConfiguration::security_cookie),
        "A pointer to a cookie that is used by Visual C++ or GS implementation."_doc)

    LIEF_COPYABLE(LoadConfiguration)
    LIEF_DEFAULT_STR(LoadConfiguration);
}
}
