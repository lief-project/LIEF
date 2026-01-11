/* Copyright 2017 - 2026 R. Thomas
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
#include "pyWriteStream.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "nanobind/utils.hpp"

#include "LIEF/iostream.hpp"

namespace LIEF::py {

void init_writerstream(nb::module_& m) {
  nb::class_<vector_iostream>(m, "WriteStream")
    .def(nb::init<>())
    .def(nb::init<bool>(), "endian_swap"_a)

    .def("reserve", &vector_iostream::reserve, "size"_a,
         nb::rv_policy::reference_internal)

    .def("increase_capacity", &vector_iostream::increase_capacity, "size"_a,
        nb::rv_policy::reference_internal)

    .def("align", &vector_iostream::align, "alignment"_a, "fill"_a = 0,
        nb::rv_policy::reference_internal)

    .def_prop_ro("size", &vector_iostream::size)
    .def("__len__", &vector_iostream::size)

    .def_prop_ro("tellp", [] (vector_iostream& self) {
      return (uint64_t)self.tellp();
    })

    .def("seekp", [] (vector_iostream& self, uint64_t pos) {
      return self.seekp(pos);
    }, "pos"_a, nb::rv_policy::reference_internal)

    .def("seek_end", &vector_iostream::seek_end,
         nb::rv_policy::reference_internal)

    .def("pad", &vector_iostream::pad, "size"_a, "value"_a = 0,
         nb::rv_policy::reference_internal)

    .def("set_endian_swap", &vector_iostream::set_endian_swap, "swap"_a)
    .def_prop_ro("endian_swap", &vector_iostream::endian_swap)

    .def_prop_ro("raw", [] (const vector_iostream& self) {
      return nb::to_memoryview(self.raw());
    }, nb::keep_alive<0, 1>())

    .def("__bytes__", [] (const vector_iostream& self) {
      return nb::to_bytes(self.raw());
    })

    .def("write_u8", [] (vector_iostream& self, uint8_t c) { return self.write<uint8_t>(c); }, nb::rv_policy::reference_internal)
    .def("write_i8", [] (vector_iostream& self, int8_t c) { return self.write<int8_t>(c); }, nb::rv_policy::reference_internal)

    .def("write_u16", [] (vector_iostream& self, uint16_t c) { return self.write<uint16_t>(c); }, nb::rv_policy::reference_internal)
    .def("write_i16", [] (vector_iostream& self, int16_t c) { return self.write<int16_t>(c); }, nb::rv_policy::reference_internal)

    .def("write_u32", [] (vector_iostream& self, uint32_t c) { return self.write<uint32_t>(c); }, nb::rv_policy::reference_internal)
    .def("write_i32", [] (vector_iostream& self, int32_t c) { return self.write<int32_t>(c); }, nb::rv_policy::reference_internal)

    .def("write_u64", [] (vector_iostream& self, uint64_t c) { return self.write<uint64_t>(c); }, nb::rv_policy::reference_internal)
    .def("write_i64", [] (vector_iostream& self, int64_t c) { return self.write<int64_t>(c); }, nb::rv_policy::reference_internal)

    .def("write_uleb128", &vector_iostream::write_uleb128, "value"_a,
      nb::rv_policy::reference_internal
    )
    .def("write_sleb128", &vector_iostream::write_sleb128, "value"_a,
      nb::rv_policy::reference_internal
    )

    .def("write", [] (vector_iostream& self, const std::string& str) {
        return self.write(str);
      }, "s"_a, nb::rv_policy::reference_internal
    )

    .def("write", [] (vector_iostream& self, nb::bytes& bytes) {
        return self.write((const uint8_t*)bytes.data(), bytes.size());
      }, "buffer"_a, nb::rv_policy::reference_internal
    )

    .def("write", [] (vector_iostream& self, const std::vector<uint8_t>& buffer) {
        return self.write(buffer);
      }, "buffer"_a, nb::rv_policy::reference_internal
    )

    .def("write", [] (vector_iostream& self, const vector_iostream& other) {
        return self.write(other);
      }, "other"_a, nb::rv_policy::reference_internal
    )

    .def("put", [] (vector_iostream& self, uint8_t c) {
        return self.put(c);
      }, "c"_a, nb::rv_policy::reference_internal
    )
  ;
}
}
