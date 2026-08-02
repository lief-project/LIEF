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
#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>

#include <limits>
#include <string>

#include "LIEF/iostream.hpp"
#include "LIEF/span.hpp"

TEST_CASE("lief.test.iostream", "[lief][test][iostream]") {
  SECTION("Span") {
    std::vector<uint8_t> buffer = {1, 2, 3, 4};
    LIEF::span<uint8_t> span_buffer = buffer;

    LIEF::vector_iostream ios;
    ios.write(span_buffer);

    REQUIRE(ios.raw() == buffer);
  }

  SECTION("u16string write grows by bytes not chars") {
    const std::u16string name = u"ABCDEFGHIJ"; // 10 chars -> 20 bytes
    const size_t byte_size = name.size() * sizeof(char16_t);

    LIEF::vector_iostream ios;
    ios.write(std::vector<uint8_t>(name.size() + 5, 0));
    ios.seekp(0);

    ios.write(name, /*with_null_char=*/false);

    // The buffer must have been grown to hold every byte written above.
    REQUIRE(ios.size() >= byte_size);

    const auto* out = reinterpret_cast<const char16_t*>(ios.raw().data());
    REQUIRE(std::u16string(out, out + name.size()) == name);
  }

  SECTION("invalid write positions are rejected") {
    using off_type = LIEF::vector_iostream::off_type;
    using pos_type = LIEF::vector_iostream::pos_type;

    LIEF::vector_iostream ios;
    ios.pad(16, 0x42);
    const std::vector<uint8_t> original = ios.raw();

    ios.seekp((pos_type)std::numeric_limits<off_type>::max());
    ios.write<uint64_t>(0);

    REQUIRE(ios.raw() == original);
    REQUIRE(ios.tellp() == std::numeric_limits<off_type>::max());

    ios.write(1, 0x43);
    REQUIRE(ios.raw() == original);
    REQUIRE(ios.tellp() == std::numeric_limits<off_type>::max());

    ios.seekp(1, std::ios_base::cur);
    REQUIRE(ios.tellp() == std::numeric_limits<off_type>::max());

    ios.seekp(0);
    ios.seekp((pos_type)-1);
    REQUIRE(ios.tellp() == 0);

    ios.seekp(-1, std::ios_base::beg);
    REQUIRE(ios.tellp() == 0);

    ios.seekp(std::numeric_limits<off_type>::min(), std::ios_base::cur);
    REQUIRE(ios.tellp() == 0);

    const size_t largest_size = std::numeric_limits<size_t>::max();
    REQUIRE(ios.edit_as<uint8_t>(largest_size) == nullptr);

    if ((uintmax_t)largest_size > (uintmax_t)std::numeric_limits<off_type>::max())
    {
      REQUIRE(ios.tellp() == 0);
    }
  }
}
