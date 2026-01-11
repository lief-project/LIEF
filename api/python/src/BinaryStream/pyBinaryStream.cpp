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
#include <optional>
#include "pyLIEF.hpp"

#include "nanobind/extra/stl/lief_result.h"
#include "nanobind/extra/stl/u16string.h"

#include <nanobind/stl/tuple.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/optional.h>

#include <LIEF/BinaryStream/BinaryStream.hpp>

namespace LIEF::py {
template<>
void create<BinaryStream>(nb::module_& m) {
  nb::class_<BinaryStream>(m, "BinaryStream")
    .def_prop_ro("size", &BinaryStream::size)
    .def("__bool__", &BinaryStream::is_valid)
    .def("__len__", &BinaryStream::size)

    .def_prop_ro("pos", &BinaryStream::pos)
    .def("increment_pos", &BinaryStream::increment_pos,
      "value"_a, nb::rv_policy::reference_internal
    )
    .def("decrement_pos", &BinaryStream::decrement_pos,
      "value"_a
    )
    .def("setpos", &BinaryStream::setpos,
      "value"_a
    )

    .def("read_uleb128", [] (BinaryStream& self) {
      size_t size = 0;
      return std::make_tuple(self.read_uleb128(&size), size);
    })

    .def("read_sleb128", [] (BinaryStream& self) {
      size_t size = 0;
      return std::make_tuple(self.read_sleb128(&size), size);
    })

    .def("read_dwarf_encoded", &BinaryStream::read_dwarf_encoded,
      "encoding"_a
    )

    .def("read_string", &BinaryStream::read_string,
      "maxsize"_a = (size_t)(-1llu)
    )

    .def("peek_string", &BinaryStream::peek_string,
      "maxsize"_a = (size_t)(-1llu)
    )

    .def("peek_string_at", &BinaryStream::peek_string_at,
      "offset"_a, "maxsize"_a = (size_t)(-1llu)
    )

    .def("read_u16string",
        nb::overload_cast<>(&BinaryStream::read_u16string, nb::const_))

    .def("read_u16string",
      nb::overload_cast<size_t>(&BinaryStream::read_u16string, nb::const_),
      "length"_a
    )

    .def("peek_u16string",
        nb::overload_cast<>(&BinaryStream::peek_u16string, nb::const_))

    .def("peek_u16string",
      nb::overload_cast<size_t>(&BinaryStream::peek_u16string, nb::const_),
      "length"_a
    )

    .def("peek_u16string",
      nb::overload_cast<size_t, size_t>(&BinaryStream::peek_u16string_at, nb::const_),
      "offset"_a, "length"_a
    )

    .def("read_mutf8",
        nb::overload_cast<size_t>(&BinaryStream::read_mutf8, nb::const_),
        "maxsize"_a = (size_t)(-1llu)
    )

    .def("peek_data",
      [] (BinaryStream& self, uint64_t offset, uint64_t size, uint64_t virtual_address) -> std::optional<nb::bytes>
      {
        std::vector<uint8_t> data;
        if (!self.peek_data(data, offset, size, virtual_address)) {
          return std::nullopt;
        }
        return nb::bytes(data.data(), data.size());
      }, "offset"_a, "size"_a, "virtual_address"_a = 0
    )

    .def("read_data",
      [] (BinaryStream& self, uint64_t size) -> std::optional<nb::bytes>
      {
        std::vector<uint8_t> data;
        if (!self.read_data(data, size)) {
          return std::nullopt;
        }
        return nb::bytes(data.data(), data.size());
      }, "size"_a
    )

    .def("read_data",
      [] (BinaryStream& self) -> std::optional<nb::bytes>
      {
        std::vector<uint8_t> data;
        if (!self.read_data(data)) {
          return std::nullopt;
        }
        return nb::bytes(data.data(), data.size());
      }
    )

    .def("align", &BinaryStream::align, "align_on"_a)
    .def("set_endian_swap", &BinaryStream::set_endian_swap, "swap"_a)

    .def("read_u8", &BinaryStream::read<uint8_t>)
    .def("read_i8", &BinaryStream::read<int8_t>)

    .def("peek_u8", nb::overload_cast<>(&BinaryStream::peek<uint8_t>, nb::const_))
    .def("peek_u8", nb::overload_cast<size_t>(&BinaryStream::peek<uint8_t>, nb::const_), "offset"_a)
    .def("peek_i8", nb::overload_cast<>(&BinaryStream::peek<int8_t>, nb::const_))
    .def("peek_i8", nb::overload_cast<size_t>(&BinaryStream::peek<int8_t>, nb::const_), "offset"_a)

    .def("read_u16", &BinaryStream::read<uint16_t>)
    .def("read_i16", &BinaryStream::read<int16_t>)

    .def("peek_u16", nb::overload_cast<>(&BinaryStream::peek<uint16_t>, nb::const_))
    .def("peek_u16", nb::overload_cast<size_t>(&BinaryStream::peek<uint16_t>, nb::const_), "offset"_a)
    .def("peek_i16", nb::overload_cast<>(&BinaryStream::peek<int16_t>, nb::const_))
    .def("peek_i16", nb::overload_cast<size_t>(&BinaryStream::peek<int16_t>, nb::const_), "offset"_a)

    .def("read_u32", &BinaryStream::read<uint32_t>)
    .def("read_i32", &BinaryStream::read<int32_t>)

    .def("peek_u32", nb::overload_cast<>(&BinaryStream::peek<uint32_t>, nb::const_))
    .def("peek_u32", nb::overload_cast<size_t>(&BinaryStream::peek<uint32_t>, nb::const_), "offset"_a)
    .def("peek_i32", nb::overload_cast<>(&BinaryStream::peek<int32_t>, nb::const_))
    .def("peek_i32", nb::overload_cast<size_t>(&BinaryStream::peek<int32_t>, nb::const_), "offset"_a)

    .def("read_u64", &BinaryStream::read<uint64_t>)
    .def("read_i64", &BinaryStream::read<int64_t>)

    .def("peek_u64", nb::overload_cast<>(&BinaryStream::peek<uint64_t>, nb::const_))
    .def("peek_u64", nb::overload_cast<size_t>(&BinaryStream::peek<uint64_t>, nb::const_), "offset"_a)
    .def("peek_i64", nb::overload_cast<>(&BinaryStream::peek<uint64_t>, nb::const_))
    .def("peek_i64", nb::overload_cast<size_t>(&BinaryStream::peek<int64_t>, nb::const_), "offset"_a)

    .def_prop_ro("start", nb::overload_cast<>(&BinaryStream::start))
    .def_prop_ro("start_addr", [] (BinaryStream& self) { return (uintptr_t)self.start(); })

    .def_prop_ro("end", nb::overload_cast<>(&BinaryStream::end))
    .def_prop_ro("end_addr", [] (BinaryStream& self) { return (uintptr_t)self.end(); })

    .def_prop_ro("p", nb::overload_cast<>(&BinaryStream::p))
    .def_prop_ro("p_addr", [] (BinaryStream& self) { return (uintptr_t)self.p(); })
  ;
}
}
