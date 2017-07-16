/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/PE/utils.hpp"
#include "LIEF/MachO/utils.hpp"
#include "LIEF/ELF/utils.hpp"

#include "pyLIEF.hpp"

void init_utils_functions(py::module& m) {

#if defined(LIEF_PE_MODULE)
    m.def("is_pe",
        static_cast<bool (*)(const std::string&)>(&LIEF::PE::is_pe),
        "Check if the given file is a ``PE``");
#endif

#if defined(LIEF_ELF_MODULE)
    m.def("is_elf",
        &LIEF::ELF::is_elf,
        "Check if the given file is an ``ELF``");
#endif

#if defined(LIEF_MACHO_MODULE)
    m.def("is_macho",
        &LIEF::MachO::is_macho,
        "Check if the given binary is ``MachO``");
#endif

}
