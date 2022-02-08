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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/ThreadCommand.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (ThreadCommand::*)(void) const;

template<class T>
using setter_t = void (ThreadCommand::*)(T);



template<>
void create<ThreadCommand>(py::module& m) {

  py::class_<ThreadCommand, LoadCommand>(m, "ThreadCommand",
      R"delim(
      Class that represents the LC_THREAD / LC_UNIXTHREAD commands and that
      can be used to get the binary entrypoint when the LC_MAIN (MainCommand) is not present

      Generally speaking, this command aims at defining the original state
      of the main thread which includes the registers' values
      )delim")

    .def_property("flavor",
        static_cast<getter_t<uint32_t>>(&ThreadCommand::flavor),
        static_cast<setter_t<uint32_t>>(&ThreadCommand::flavor),
        R"delim(
        Integer that defines a special *flavor* for the thread.

        The meaning of this value depends on the :attr:`~lief.MachO.ThreadCommand.architecture`.
        The list of the values can be found in the XNU kernel files:

        - xnu/osfmk/mach/arm/thread_status.h  for the ARM/AArch64 architectures
        - xnu/osfmk/mach/i386/thread_status.h for the x86/x86-64 architectures
        )delim")


    .def_property("state",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&ThreadCommand::state),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&ThreadCommand::state),
        R"delim(
        The actual thread state as a vector of bytes. Depending on the architecture(),
        these data can be casted into x86_thread_state_t, x86_thread_state64_t, ...
        )delim")


    .def_property("count",
        static_cast<getter_t<uint32_t>>(&ThreadCommand::count),
        static_cast<setter_t<uint32_t>>(&ThreadCommand::count),
        R"delim(
        Size of the thread state data with 32-bits alignment.

        This value should match len(:attr:`~lief.MachO.ThreadCommand.state`)
        )delim")

    .def_property_readonly("pc",
        static_cast<getter_t<uint64_t>>(&ThreadCommand::pc),
        R"delim(
        Return the initial Program Counter regardless of the underlying architecture.
        This value, when non null, can be used to determine the binary's entrypoint.

        Underneath, it works by looking for the PC register value in the :attr:`~lief.MachO.ThreadCommand.state` data
        )delim")

    .def_property("architecture",
        static_cast<getter_t<CPU_TYPES>>(&ThreadCommand::architecture),
        static_cast<setter_t<CPU_TYPES>>(&ThreadCommand::architecture),
        "The CPU architecture that is targeted by this ThreadCommand")

    .def("__eq__", &ThreadCommand::operator==)
    .def("__ne__", &ThreadCommand::operator!=)
    .def("__hash__",
        [] (const ThreadCommand& thread) {
          return LIEF::Hash::hash(thread);
        })


    .def("__str__",
        [] (const ThreadCommand& thread)
        {
          std::ostringstream stream;
          stream << thread;
          std::string str = stream.str();
          return str;
        });

}

}
}
