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

#include "LIEF/PE/utils.hpp"
#include "LIEF/MachO/utils.hpp"
#include "LIEF/ELF/utils.hpp"

#include "LIEF/OAT.hpp"
#include "LIEF/DEX.hpp"
#include "LIEF/VDEX.hpp"
#include "LIEF/ART.hpp"

#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#include "pyLIEF.hpp"

void init_utils_functions(py::module& m) {


  m.def("shell",
    [] (void) {
      const auto& InteractiveShellEmbed = py::module::import("IPython").attr("terminal").attr("embed").attr("InteractiveShellEmbed");
      const auto& ipshell = InteractiveShellEmbed("banner1"_a = "Dropping into IPython", "exit_msg"_a = "Leaving Interpreter, back to program.");
      return ipshell();
    },
    "Drop into an IPython Interpreter");


  m.def("demangle", [] (const std::string& name) -> py::object {
  #if defined(__unix__)
    int status;
    char* demangled_name = abi::__cxa_demangle(name.c_str(), 0, 0, &status);
    if (status == 0) {
      std::string realname = demangled_name;
      free(demangled_name);
      return py::str(realname);
    } else {
      return py::none();
    }
  #else
      return py::none();
  #endif
  });

  m.def("breakp",
      [] (void) {
        py::object set_trace = py::module::import("pdb").attr("set_trace");
        return set_trace();
      },
      "Trigger 'pdb.set_trace()'");

#if defined(LIEF_PE_SUPPORT)
    m.def("is_pe",
        static_cast<bool (*)(const std::string&)>(&LIEF::PE::is_pe),
        "Check if the given file is a ``PE`` (from filename)",
        "filename"_a);

    m.def("is_pe",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::PE::is_pe),
        "Check if the given raw data is a ``PE``",
        "raw"_a);
#endif

#if defined(LIEF_ELF_SUPPORT)
    m.def("is_elf",
        static_cast<bool (*)(const std::string&)>(&LIEF::ELF::is_elf),
        "Check if the given file is an ``ELF``",
        "filename"_a);


    m.def("is_elf",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::ELF::is_elf),
        "Check if the given raw data is an ``ELF``",
        "raw"_a);
#endif

#if defined(LIEF_MACHO_SUPPORT)
    m.def("is_macho",
        static_cast<bool (*)(const std::string&)>(&LIEF::MachO::is_macho),
        "Check if the given file is a ``MachO`` (from filename)",
        "filename"_a);


    m.def("is_macho",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::MachO::is_macho),
        "Check if the given raw data is a ``MachO``",
        "raw"_a);

#endif


#if defined(LIEF_OAT_SUPPORT)
    m.def("is_oat",
        static_cast<bool (*)(const std::string&)>(&LIEF::OAT::is_oat),
        "Check if the given file is an ``OAT`` (from filename)",
        "filename"_a);


    m.def("is_oat",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::OAT::is_oat),
        "Check if the given raw data is an ``OAT``",
        "raw"_a);

    m.def("is_oat",
        static_cast<bool (*)(const LIEF::ELF::Binary&)>(&LIEF::OAT::is_oat),
        "Check if the given " RST_CLASS_REF(lief.ELF.Binary) " is an ``OAT``",
        "elf"_a);


    m.def("oat_version",
        static_cast<LIEF::OAT::oat_version_t (*)(const std::string&)>(&LIEF::OAT::version),
        "Return the OAT version of the given file",
        "filename"_a);


    m.def("oat_version",
        static_cast<LIEF::OAT::oat_version_t (*)(const std::vector<uint8_t>&)>(&LIEF::OAT::version),
        "Return the OAT version of the raw data",
        "raw"_a);

    m.def("oat_version",
        static_cast<LIEF::OAT::oat_version_t (*)(const LIEF::ELF::Binary&)>(&LIEF::OAT::version),
        "Return the OAT version of the given " RST_CLASS_REF(lief.ELF.Binary) "",
        "elf"_a);

#endif

#if defined(LIEF_DEX_SUPPORT)
    m.def("is_dex",
        static_cast<bool (*)(const std::string&)>(&LIEF::DEX::is_dex),
        "Check if the given file is a ``DEX`` (from filename)",
        "filename"_a);


    m.def("is_dex",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::DEX::is_dex),
        "Check if the given raw data is a ``DEX``",
        "raw"_a);

    m.def("dex_version",
        static_cast<LIEF::DEX::dex_version_t (*)(const std::string&)>(&LIEF::DEX::version),
        "Return the OAT version of the given file",
        "filename"_a);


    m.def("dex_version",
        static_cast<LIEF::DEX::dex_version_t (*)(const std::vector<uint8_t>&)>(&LIEF::DEX::version),
        "Return the DEX version of the raw data",
        "raw"_a);

#endif


#if defined(LIEF_VDEX_SUPPORT)
    m.def("is_vdex",
        static_cast<bool (*)(const std::string&)>(&LIEF::VDEX::is_vdex),
        "Check if the given file is a ``VDEX`` (from filename)",
        "filename"_a);

    m.def("is_vdex",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::VDEX::is_vdex),
        "Check if the given raw data is a ``VDEX``",
        "raw"_a);

    m.def("vdex_version",
        static_cast<LIEF::VDEX::vdex_version_t (*)(const std::string&)>(&LIEF::VDEX::version),
        "Return the VDEX version of the given file",
        "filename"_a);


    m.def("vdex_version",
        static_cast<LIEF::VDEX::vdex_version_t (*)(const std::vector<uint8_t>&)>(&LIEF::VDEX::version),
        "Return the VDEX version of the raw data",
        "raw"_a);

#endif


#if defined(LIEF_ART_SUPPORT)
    m.def("is_art",
        static_cast<bool (*)(const std::string&)>(&LIEF::ART::is_art),
        "Check if the given file is an ``ART`` (from filename)",
        "filename"_a);

    m.def("is_art",
        static_cast<bool (*)(const std::vector<uint8_t>&)>(&LIEF::ART::is_art),
        "Check if the given raw data is an ``ART``",
        "raw"_a);

    m.def("art_version",
        static_cast<LIEF::ART::art_version_t (*)(const std::string&)>(&LIEF::ART::version),
        "Return the ART version of the given file",
        "filename"_a);


    m.def("art_version",
        static_cast<LIEF::ART::art_version_t (*)(const std::vector<uint8_t>&)>(&LIEF::ART::version),
        "Return the ART version of the raw data",
        "raw"_a);

#endif


}
