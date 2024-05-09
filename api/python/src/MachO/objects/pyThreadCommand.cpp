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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include "nanobind/utils.hpp"

#include "LIEF/MachO/ThreadCommand.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<ThreadCommand>(nb::module_& m) {

  nb::class_<ThreadCommand, LoadCommand>(m, "ThreadCommand",
      R"delim(
      Class that represents the LC_THREAD / LC_UNIXTHREAD commands and that
      can be used to get the binary entrypoint when the LC_MAIN (MainCommand) is not present

      Generally speaking, this command aims at defining the original state
      of the main thread which includes the registers' values
      )delim"_doc)
    .def(nb::init<uint32_t, uint32_t, Header::CPU_TYPE>())

    .def_prop_rw("flavor",
        nb::overload_cast<>(&ThreadCommand::flavor, nb::const_),
        nb::overload_cast<uint32_t>(&ThreadCommand::flavor),
        R"delim(
        Integer that defines a special *flavor* for the thread.

        The meaning of this value depends on the :attr:`~lief.MachO.ThreadCommand.architecture`.
        The list of the values can be found in the XNU kernel files:

        - xnu/osfmk/mach/arm/thread_status.h  for the ARM/AArch64 architectures
        - xnu/osfmk/mach/i386/thread_status.h for the x86/x86-64 architectures
        )delim"_doc)


    .def_prop_rw("state",
        [] (const ThreadCommand& self) {
          return nb::to_memoryview(self.state());
        },
        nb::overload_cast<std::vector<uint8_t>>(&ThreadCommand::state),
        R"delim(
        The actual thread state as a vector of bytes. Depending on the architecture(),
        these data can be casted into x86_thread_state_t, x86_thread_state64_t, ...
        )delim"_doc)


    .def_prop_rw("count",
        nb::overload_cast<>(&ThreadCommand::count, nb::const_),
        nb::overload_cast<uint32_t>(&ThreadCommand::count),
        R"delim(
        Size of the thread state data with 32-bits alignment.

        This value should match len(:attr:`~lief.MachO.ThreadCommand.state`)
        )delim"_doc)

    .def_prop_ro("pc",
        nb::overload_cast<>(&ThreadCommand::pc, nb::const_),
        R"delim(
        Return the initial Program Counter regardless of the underlying architecture.
        This value, when non null, can be used to determine the binary's entrypoint.

        Underneath, it works by looking for the PC register value in the :attr:`~lief.MachO.ThreadCommand.state` data
        )delim"_doc)

    .def_prop_rw("architecture",
        nb::overload_cast<>(&ThreadCommand::architecture, nb::const_),
        nb::overload_cast<Header::CPU_TYPE>(&ThreadCommand::architecture),
        "The CPU architecture that is targeted by this ThreadCommand"_doc)

    LIEF_DEFAULT_STR(ThreadCommand);
}
}
