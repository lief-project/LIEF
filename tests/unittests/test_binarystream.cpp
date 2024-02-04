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
#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>

#include "utils.hpp"

#include <LIEF/BinaryStream/BinaryStream.hpp>
#include <LIEF/BinaryStream/MemoryStream.hpp>
#include <LIEF/BinaryStream/SpanStream.hpp>
#include <LIEF/BinaryStream/VectorStream.hpp>
#include <LIEF/BinaryStream/FileStream.hpp>

using namespace LIEF;

TEST_CASE("lief.test.binarystream", "[lief][test][binarystream]") {
  SECTION("MemoryStream") {
    std::vector<uint8_t> buffer = {
      0x00, 0x10, 0x23, 0x40
    };
    const auto buffer_addr = reinterpret_cast<uintptr_t>(buffer.data());

    MemoryStream stream(buffer_addr, buffer.size());
    REQUIRE(stream.base_address() == buffer_addr);
    REQUIRE(stream.binary() == nullptr);
    REQUIRE(stream.pos() == 0);
    REQUIRE(stream.size() == buffer.size());
    REQUIRE(stream.end() == buffer.data() + buffer.size());
    REQUIRE(stream.peek<uint8_t>()  == 0x00);
    REQUIRE(stream.peek<uint8_t>(1) == 0x10);
    REQUIRE(stream.peek<uint8_t>(3) == 0x40);
    REQUIRE(MemoryStream::classof(stream));
  }

  SECTION("FileStream") {
    const std::string& filepath = test::get_sample("PE", "PE64_x86-64_library_libLIEF.dll");

    auto fstream = FileStream::from_file(filepath);
    REQUIRE(fstream);
    FileStream& fs = *fstream;
    REQUIRE(FileStream::classof(fs));

    std::vector<uint8_t> buffer;
    fs.peek_data(buffer, std::numeric_limits<uint32_t>::max(), 4);
    REQUIRE(buffer.empty());

    fs.peek_data(buffer, 0, 4);
    REQUIRE(!buffer.empty());
    REQUIRE(buffer.size() == 4);
  }

  SECTION("VectorStream") {
    std::vector<uint8_t> buffer{1, 2, 3};
    VectorStream vs(buffer);
    REQUIRE(VectorStream::classof(vs));

    REQUIRE(vs.p() == vs.content().data());
    REQUIRE(vs.start() == vs.p());
    REQUIRE(vs.end() == vs.content().data() + vs.content().size());
    REQUIRE(static_cast<VectorStream&>(vs).p() == static_cast<const VectorStream&>(vs).p());
    REQUIRE(static_cast<VectorStream&>(vs).end() == static_cast<const VectorStream&>(vs).end());
    REQUIRE(static_cast<VectorStream&>(vs).start() == static_cast<const VectorStream&>(vs).start());
    vs.read<uint8_t>();

    REQUIRE(vs.p() != vs.content().data());
    REQUIRE(vs.start() != vs.p());
  }

}
