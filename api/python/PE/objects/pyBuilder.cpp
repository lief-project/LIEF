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

#include "LIEF/PE/Builder.hpp"

#include <string>
#include <sstream>

//template<typename Fn, typename... Args,
//        std::enable_if_t<std::is_member_pointer<std::decay_t<Fn>>{}, int> = 0 >
//constexpr decltype(auto) my_invoke(Fn&& f, Args&&... args)
//    noexcept(noexcept(std::mem_fn(f)(std::forward<Args>(args)...)))
//{
//    return std::mem_fn(f)(std::forward<Args>(args)...);
//}

namespace LIEF {
namespace PE {

template<>
void create<Builder>(py::module& m) {

  py::class_<Builder>(m, "Builder",
      R"delim(
      Class that is used to rebuild a raw PE binary from a PE::Binary object
      )delim")

    .def(py::init<Binary&>(),
        "Constructor that takes a " RST_CLASS_REF(lief.PE.Binary) "",
        "pe_binary"_a)

    .def("build",
        [] (Builder& self) -> py::object {
          return error_or(static_cast<ok_error_t(Builder::*)()>(&Builder::build), self);
        },
        "Perform the build process")

    .def("build_imports",
        &Builder::build_imports,
        "Rebuild the import table into another section",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("patch_imports",
        &Builder::patch_imports,
        "Patch the original import table in order to redirect functions to "
        "the new import table.\n\n"
        "This setting should be used with ``build_imports`` set to ``True``",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("build_relocations",
        &Builder::build_relocations,
        "Rebuild the relocation table in another section",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("build_tls",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_tls),
        "Rebuild TLS object in another section",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("build_resources",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_resources),
        "Rebuid the resources in another section",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("build_overlay",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_overlay),
        "Rebuild the binary's overlay",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("build_dos_stub",
        static_cast<Builder& (Builder::*)(bool)>(&Builder::build_dos_stub),
        "Rebuild the DOS stub",
        py::arg("enable") = true,
        py::return_value_policy::reference)

    .def("write",
        static_cast<void (Builder::*)(const std::string&) const>(&Builder::write),
        "Write the build result into the ``output`` file",
        "output"_a)

    .def("get_build",
        &Builder::get_build,
        "Return the build result as a ``list`` of bytes",
        py::return_value_policy::reference_internal)


    .def("__str__",
        [] (const Builder& builder) {
          std::ostringstream stream;
          stream << builder;
          std::string str = stream.str();
          return str;
        });

}

}
}
