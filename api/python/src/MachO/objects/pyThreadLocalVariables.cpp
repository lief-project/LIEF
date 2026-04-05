/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include <nanobind/stl/string.h>

#include "LIEF/MachO/ThreadLocalVariables.hpp"
#include "LIEF/MachO/Section.hpp"

#include "MachO/pyMachO.hpp"
#include "nanobind/extra/random_access_iterator.hpp"
#include "nanobind/extra/stl/lief_optional.h"

namespace LIEF::MachO::py {

template<>
void create<ThreadLocalVariables>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<ThreadLocalVariables, Section> cls(m, "ThreadLocalVariables",
    R"doc(
    This class represents a MachO section whose type is
    :attr:`~lief.MachO.Section.TYPE.THREAD_LOCAL_VARIABLES`.

    It contains an array of thread-local variable descriptors
    (:class:`~.ThreadLocalVariables.Thunk`) used by dyld to lazily initialize
    thread-local storage on first access.
    )doc"_doc);

  nb::class_<ThreadLocalVariables::Thunk> thunk(cls, "Thunk",
    R"doc(
    Descriptor for a single thread-local variable.

    The layout mirrors the ``tlv_descriptor`` structure from ``<mach-o/loader.h>``.
    )doc"_doc);

  thunk
    .def(nb::init<>())
    .def(nb::init<uint64_t, uint64_t, uint64_t>(),
        "func"_a, "key"_a, "offset"_a)
    .def_rw("func", &ThreadLocalVariables::Thunk::func,
        "Address of the initializer function (``tlv_thunk``)"_doc)
    .def_rw("key", &ThreadLocalVariables::Thunk::key,
        "``pthread_key_t`` key used by the runtime"_doc)
    .def_rw("offset", &ThreadLocalVariables::Thunk::offset,
        "Offset of the variable in the TLS block"_doc)
    .def("__str__", &ThreadLocalVariables::Thunk::to_string);

  cls
    .def_prop_ro("thunks",
        [] (const ThreadLocalVariables& self) {
          auto range = self.thunks();
          return nb::make_random_access_iterator<nb::rv_policy::copy>(
            nb::type<ThreadLocalVariables>(), "thunks_it", range
          );
        },
        R"doc(
        Return an iterator over the :class:`~.ThreadLocalVariables.Thunk`
        descriptors stored in this section.
        )doc"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("nb_thunks", &ThreadLocalVariables::nb_thunks,
        "Number of :class:`~.ThreadLocalVariables.Thunk` descriptors"_doc)

    .def("get", &ThreadLocalVariables::get,
        R"doc(
        Return the :class:`~.ThreadLocalVariables.Thunk` at the given index, or
        None if the index is out of range.
        )doc"_doc, "idx"_a)

    .def("set", &ThreadLocalVariables::set,
        R"doc(
        Change the :class:`~.ThreadLocalVariables.Thunk` at the given index.
        )doc"_doc, "idx"_a, "thunk"_a)

    .def("__getitem__",
        nb::overload_cast<size_t>(&ThreadLocalVariables::operator[], nb::const_),
        R"doc(
        Return the :class:`~.ThreadLocalVariables.Thunk` at the given index, or
        None if the index is out of range.
        )doc"_doc, "idx"_a)

    .def("__setitem__",
        nb::overload_cast<size_t, const ThreadLocalVariables::Thunk&>(&ThreadLocalVariables::set),
        R"doc(
        Change the :class:`~.ThreadLocalVariables.Thunk` at the given index.
        )doc"_doc, "idx"_a, "thunk"_a);
}

}
