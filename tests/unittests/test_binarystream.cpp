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
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "utils.hpp"

#include <LIEF/BinaryStream/BinaryStream.hpp>
#include <LIEF/BinaryStream/FileStream.hpp>
#include <LIEF/BinaryStream/MemoryStream.hpp>
#include <LIEF/BinaryStream/SpanStream.hpp>
#include <LIEF/BinaryStream/VectorStream.hpp>

using namespace LIEF;

TEST_CASE("lief.test.binarystream", "[lief][test][binarystream]") {
  SECTION("MemoryStream") {
    std::vector<uint8_t> buffer = {0x00, 0x10, 0x23, 0x40};
    const auto buffer_addr = reinterpret_cast<uintptr_t>(buffer.data());

    MemoryStream stream(buffer_addr, buffer.size());
    CHECK(stream.base_address() == buffer_addr);
    CHECK(stream.binary() == nullptr);
    CHECK(stream.pos() == 0);
    CHECK(stream.size() == buffer.size());
    CHECK(stream.end() == buffer.data() + buffer.size());
    CHECK(stream.peek<uint8_t>() == 0x00);
    CHECK(stream.peek<uint8_t>(1) == 0x10);
    CHECK(stream.peek<uint8_t>(3) == 0x40);
    CHECK(MemoryStream::classof(stream));
  }

  SECTION("FileStream") {
    const std::string& filepath =
        test::get_sample("PE", "PE64_x86-64_library_libLIEF.dll");

    auto fstream = FileStream::from_file(filepath);
    REQUIRE(fstream);
    FileStream& fs = *fstream;
    CHECK(FileStream::classof(fs));

    std::vector<uint8_t> buffer;
    fs.peek_data(buffer, std::numeric_limits<uint32_t>::max(), 4);
    CHECK(buffer.empty());

    fs.peek_data(buffer, 0, 4);
    CHECK_FALSE(buffer.empty());
    CHECK(buffer.size() == 4);
  }

  SECTION("VectorStream") {
    std::vector<uint8_t> buffer{1, 2, 3};
    VectorStream vs(buffer);
    CHECK(VectorStream::classof(vs));

    CHECK(vs.p() == vs.content().data());
    CHECK(vs.start() == vs.p());
    CHECK(vs.end() == vs.content().data() + vs.content().size());
    CHECK(static_cast<VectorStream&>(vs).p() ==
          static_cast<const VectorStream&>(vs).p());
    CHECK(static_cast<VectorStream&>(vs).end() ==
          static_cast<const VectorStream&>(vs).end());
    CHECK(static_cast<VectorStream&>(vs).start() ==
          static_cast<const VectorStream&>(vs).start());
    vs.read<uint8_t>();

    CHECK(vs.p() != vs.content().data());
    CHECK(vs.start() != vs.p());
  }

  SECTION("VectorStream-slice") {
    std::vector<uint8_t> buffer(256);
    for (size_t i = 0; i < buffer.size(); ++i) {
      buffer[i] = static_cast<uint8_t>(i);
    }
    VectorStream vs(std::move(buffer));

    // Slice with offset and size
    auto sliced = vs.slice(10, 20);
    REQUIRE(sliced != nullptr);
    CHECK(sliced->size() == 20);

    // Slice with only offset
    auto sliced2 = vs.slice(100);
    REQUIRE(sliced2 != nullptr);
    CHECK(sliced2->size() == 156);

    // Out of bounds
    auto sliced3 = vs.slice(300, 10);
    CHECK(sliced3 == nullptr);
  }

  SECTION("SpanStream-to_vector") {
    std::vector<uint8_t> buffer = {0xDE, 0xAD, 0xBE, 0xEF};
    SpanStream ss(buffer);
    auto vec = ss.to_vector();
    REQUIRE(vec != nullptr);
    CHECK(vec->size() == 4);
  }

  SECTION("FileStream-content") {
    const std::string& filepath =
        test::get_sample("PE", "PE64_x86-64_library_libLIEF.dll");
    auto fstream = FileStream::from_file(filepath);
    REQUIRE(fstream);
    auto content = fstream->content();
    CHECK(content.size() == fstream->size());
  }

  SECTION("BinaryStream-read_string") {
    std::vector<uint8_t> buffer = {'H', 'e', 'l', 'l', 'o', '\0', 'W'};
    SpanStream ss(buffer);
    auto str = ss.read_string();
    REQUIRE(str);
    CHECK(*str == "Hello");
    CHECK(ss.pos() == 6);
  }

  SECTION("BinaryStream-read_u16string") {
    // "Hi\0" in UTF-16LE
    std::vector<uint8_t> buffer = {
        'H', 0, 'i', 0, 0, 0,
    };
    SpanStream ss(buffer);
    auto str = ss.read_u16string();
    REQUIRE(str);
    CHECK(str->size() == 2);
  }

  SECTION("BinaryStream-align") {
    std::vector<uint8_t> buffer(64, 0);
    SpanStream ss(buffer);
    ss.read<uint8_t>(); // pos = 1
    size_t pad = ss.align(4);
    CHECK(pad == 3);
    CHECK(ss.pos() == 4);

    // Already aligned
    size_t pad2 = ss.align(4);
    CHECK(pad2 == 0);

    // align_on = 0
    size_t pad3 = ss.align(0);
    CHECK(pad3 == 0);
  }

  SECTION("BinaryStream-read_uleb128") {
    // 624485 encoded as ULEB128: 0xE5 0x8E 0x26
    std::vector<uint8_t> buffer = {0xE5, 0x8E, 0x26};
    SpanStream ss(buffer);
    size_t sz = 0;
    auto val = ss.read_uleb128(&sz);
    REQUIRE(val);
    CHECK(*val == 624485);
    CHECK(sz == 3);
  }

  SECTION("BinaryStream-read_sleb128") {
    // -123456 encoded as SLEB128: 0xC0 0xBB 0x78
    std::vector<uint8_t> buffer = {0xC0, 0xBB, 0x78};
    SpanStream ss(buffer);
    size_t sz = 0;
    auto val = ss.read_sleb128(&sz);
    REQUIRE(val);
    CHECK(static_cast<int64_t>(*val) == -123456);
    CHECK(sz == 3);
  }

  SECTION("BinaryStream-read_sleb128-sign-extension") {
    auto [buffer, expected] = GENERATE(table<std::vector<uint8_t>, int64_t>({
        {{0x7f}, -1},
        {{0x40}, -64},
        {{0xbf, 0x7f}, -65},
        {{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}, INT64_MIN},
    }));
    CAPTURE(buffer, expected);
    SpanStream ss(buffer);
    size_t sz = 0;
    auto val = ss.read_sleb128(&sz);
    REQUIRE(val);
    CHECK(static_cast<int64_t>(*val) == expected);
    CHECK(sz == buffer.size());
  }

  SECTION("BinaryStream-read_dwarf_encoded") {
    // clang-format off
    auto [encoding, buffer, expected] =
        GENERATE(table<uint8_t, std::vector<uint8_t>, int64_t>({
          {/*UDATA2=*/0x02,  {0x34, 0x12},             0x1234},
          {/*UDATA4=*/0x03,  {0x78, 0x56, 0x34, 0x12}, 0x12345678},
          {/*UDATA8=*/0x04,  {1, 0, 0, 0, 0, 0, 0, 0}, 1},
          {/*ULEB128=*/0x01, {0x7F},                   127},
          {/*SLEB128=*/0x09, {0x7F},                   -1},
          {/*unknown=*/0x00, {0x00},                   0},
        }));
    // clang-format on
    CAPTURE(encoding);
    SpanStream ss(buffer);
    auto val = ss.read_dwarf_encoded(encoding);
    REQUIRE(val);
    CHECK(*val == expected);
  }

  SECTION("BinaryStream.ULEB128") {
    SECTION("Largest value") {
      // UINT64_MAX encoded on the maximum of 10 bytes
      std::vector<uint8_t> buffer = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xFF, 0xFF, 0xFF, 0xFF, 0x01};
      SpanStream ss(buffer);
      size_t sz = 0;
      auto val = ss.read_uleb128(&sz);
      REQUIRE(val);
      CHECK(*val == std::numeric_limits<uint64_t>::max());
      CHECK(sz == 10);
    }

    SECTION("Invalid encodings") {
      auto [kind, buffer, error] =
          GENERATE(table<std::string, std::vector<uint8_t>, lief_errors>({
              {"overflow",
               {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02},
               lief_errors::corrupted},
              {"non-canonical", std::vector<uint8_t>(10, 0x80),
               lief_errors::corrupted},
              {"truncated stream", {0x80}, lief_errors::read_error},
              {"smallest non-canonical overflow",
               {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                0x00},
               lief_errors::corrupted},
          }));
      CAPTURE(kind);
      SpanStream ss(buffer);
      auto val = ss.read_uleb128();
      REQUIRE_FALSE(val);
      CHECK(val.error() == error);
    }
  }

  SECTION("BinaryStream.SLEB128") {
    SECTION("Valid encodings") {
      auto [buffer, expected] = GENERATE(table<std::vector<uint8_t>, int64_t>({
          {{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F},
           std::numeric_limits<int64_t>::min()},
          {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
           std::numeric_limits<int64_t>::max()},
          {{0x7F}, -1},
      }));
      CAPTURE(buffer, expected);
      SpanStream ss(buffer);
      size_t sz = 0;
      auto val = ss.read_sleb128(&sz);
      REQUIRE(val);
      CHECK(static_cast<int64_t>(*val) == expected);
      CHECK(sz == buffer.size());
    }

    SECTION("Invalid encodings") {
      auto [kind, buffer, error] =
          GENERATE(table<std::string, std::vector<uint8_t>, lief_errors>({
              {"non-canonical", std::vector<uint8_t>(10, 0x80),
               lief_errors::corrupted},
              {"truncated stream", {0x80}, lief_errors::read_error},
          }));
      CAPTURE(kind);
      SpanStream ss(buffer);
      auto val = ss.read_sleb128();
      REQUIRE_FALSE(val);
      CHECK(val.error() == error);
    }
  }

  SECTION("MemoryStream-read-error") {
    std::vector<uint8_t> buffer = {0x00, 0x10, 0x23, 0x40};
    const auto buffer_addr = reinterpret_cast<uintptr_t>(buffer.data());
    MemoryStream stream(buffer_addr, buffer.size());

    // Out of bounds peek
    auto result = stream.peek<uint32_t>(100);
    CHECK_FALSE(result);
  }

  SECTION("FileStream-from_file-error") {
    auto fstream = FileStream::from_file("/does/not/exist/at/all");
    CHECK_FALSE(fstream);
  }

  SECTION("VectorStream-from_file-error") {
    auto vs = VectorStream::from_file("/does/not/exist/at/all");
    CHECK_FALSE(vs);
  }

  SECTION("FileStream-from_file-directory") {
    auto fstream = FileStream::from_file(test::get_sample_dir());
    CHECK_FALSE(fstream);
  }

  SECTION("VectorStream-from_file-directory") {
    auto vs = VectorStream::from_file(test::get_sample_dir());
    CHECK_FALSE(vs);
  }
}
