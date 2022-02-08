/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (LoadConfiguration::*)(void) const;

template<class T>
using setter_t = void (LoadConfiguration::*)(T);


template<>
void create<LoadConfiguration>(py::module& m) {
  py::class_<LoadConfiguration, LIEF::Object>(m, "LoadConfiguration",
    R"delim(
    Class that represents the default PE's ``LoadConfiguration``
    It's the base class for any future versions of the structure
    )delim")
    .def(py::init<>())

    .def_property_readonly("version",
        &LoadConfiguration::version,
        "(SDK) Version of the structure. (" RST_CLASS_REF(lief.PE.WIN_VERSION) ")")

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::characteristics),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::characteristics),
        "Characteristics of the structure.")

    .def_property_readonly("size",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::size),
        "Size of the structure which is an alias for " RST_ATTR_REF(lief.PE.LoadConfiguration.characteristics) "")

    .def_property("timedatestamp",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::timedatestamp),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::timedatestamp),
        "Date and time stamp value")

    .def_property("major_version",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::major_version),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::major_version),
        "Major Version")

    .def_property("minor_version",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::minor_version),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::minor_version),
        "Minor version")

    .def_property("global_flags_clear",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::global_flags_clear),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::global_flags_clear),
        "The global loader flags to clear for this process as the loader start the process.")

    .def_property("global_flags_set",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::global_flags_set),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::global_flags_set),
        "The global loader flags to set for this process as the loader starts the process.")

    .def_property("critical_section_default_timeout",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::critical_section_default_timeout),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::critical_section_default_timeout),
        "The default timeout value to use for is process’s critical sections that are abandoned.")

    .def_property("decommit_free_block_threshold",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::decommit_free_block_threshold),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::decommit_free_block_threshold),
        "Memory that must be freed before it is returned to the system, in bytes.")

    .def_property("decommit_total_free_threshold",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::decommit_total_free_threshold),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::decommit_total_free_threshold),
        "Total amount of free memory, in bytes")

    .def_property("lock_prefix_table",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::lock_prefix_table),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::lock_prefix_table),
        "The **VA** of a list of addresses where the ``LOCK`` prefix "
        "is used so that they can be replaced with ``NOP`` on single processor machines.")

    .def_property("maximum_allocation_size",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::maximum_allocation_size),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::maximum_allocation_size),
        "Maximum allocation size, in bytes.")

    .def_property("virtual_memory_threshold",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::virtual_memory_threshold),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::virtual_memory_threshold),
        "Maximum virtual memory size, in bytes.")

    .def_property("process_affinity_mask",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::process_affinity_mask),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::process_affinity_mask),
        "Setting this field to a non-zero value is equivalent to calling "
        "``SetProcessAffinityMask`` with this value during process startup (.exe only)")

    .def_property("process_heap_flags",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::process_heap_flags),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::process_heap_flags),
        R"delim(
        Process heap flags that correspond to the first argument of the ``HeapCreate``
        function. These flags apply to the process heap that is created during process startup.
        )delim")

    .def_property("csd_version",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::csd_version),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::csd_version),
        "The service pack version identifier.")

    .def_property("reserved1",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::reserved1),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::reserved1),
        "Must be zero.")

    .def_property("dependent_load_flags",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::dependent_load_flags),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::dependent_load_flags),
        "On recent the version of the structure, Microsoft renamed reserved1 to DependentLoadFlags. "
        "This is an alias for " RST_ATTR_REF(lief.PE.LoadConfiguration.reserved1) "")

    .def_property("editlist",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::editlist),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::editlist),
        "Reserved for use by the system.")

    .def_property("security_cookie",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::security_cookie),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::security_cookie),
        "A pointer to a cookie that is used by Visual C++ or GS implementation.")

    .def("__eq__", &LoadConfiguration::operator==)
    .def("__ne__", &LoadConfiguration::operator!=)
    .def("__hash__",
        [] (const LoadConfiguration& config) {
          return Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfiguration& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });
}

}
}
