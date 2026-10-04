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
#include <LIEF/utils.hpp>
#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>
using namespace LIEF;

TEST_CASE("lief.test.utils", "[lief][test][utils]") {

  SECTION("align") {
    REQUIRE(align(30, 0) == 30);
    REQUIRE(align(3, 8) == 8);
    REQUIRE(align(15, 16) == 16);
    REQUIRE(align(29, 16) == 32);
  }

  SECTION("round") {
    REQUIRE(LIEF::round(1) == 1);
    REQUIRE(LIEF::round(0x99) == 0x100);
    REQUIRE(LIEF::round(0x10000) == 0x10000);
    REQUIRE(LIEF::round(std::numeric_limits<uint16_t>::max() - 1) == 0x10000);
  }

  SECTION("size_literal") {
    REQUIRE(2_KB == 2048);
    REQUIRE(3_MB == 3072_KB);
    REQUIRE(4_GB == 4096_MB);
  }

  SECTION("u16tou8") {
    const auto convert = [](const std::u16string& str, bool remove_null = false) {
      result<std::string> u8 = u16tou8(str, remove_null);
      REQUIRE(u8.has_value());
      return *u8;
    };

    const auto is_invalid = [](const std::u16string& str) {
      result<std::string> u8 = u16tou8(str);
      return !u8 && u8.error() == lief_errors::conversion_error;
    };

    CHECK(convert(u"").empty());
    CHECK(convert(u"abc") == "abc");
    CHECK(convert({0x00E9, 0x20AC}) == "\xc3\xa9\xe2\x82\xac");
    CHECK(convert({0xFFFF}) == "\xef\xbf\xbf");

    // Surrogate pairs
    CHECK(convert({0xD83D, 0xDE00}) == "\xf0\x9f\x98\x80");
    CHECK(convert({u'a', 0xD83D, 0xDE00, u'z'}) == "a\xf0\x9f\x98\x80z");
    CHECK(convert({0xDBFF, 0xDFFF}) == "\xf4\x8f\xbf\xbf");

    // Unpaired surrogates
    CHECK(is_invalid({0xD800, u'a'}));
    CHECK(is_invalid({0xDC00, u'a'}));
    CHECK(is_invalid({u'a', 0xD83D}));
    CHECK(is_invalid({0xDE00, 0xD83D}));
    CHECK(is_invalid({0xD83D, 0xD83D, 0xDE00}));

    // Byte order mark
    CHECK(convert({0xFEFF, u'a'}) == "a");
    CHECK(convert({0xFEFF, 0xFEFF}) == "\xef\xbb\xbf");
    CHECK(convert({0xFFFE, 0x6100, 0x3DD8, 0x00DE}) == "a\xf0\x9f\x98\x80");

    // Null characters
    CHECK(convert({u'a', 0, u'b'}) == std::string("a\0b", 3));
    CHECK(convert({u'a', 0, u'b'}, /*remove_null=*/true) == "a");
    CHECK(convert({0xD83D, 0xDE00, 0, 0xD800}, /*remove_null=*/true) ==
          "\xf0\x9f\x98\x80");

    result<std::u16string> u16 = u8tou16("a\xf0\x9f\x98\x80");
    REQUIRE(u16.has_value());
    CHECK(*u16 == std::u16string{u'a', 0xD83D, 0xDE00});
    CHECK(convert(*u16) == "a\xf0\x9f\x98\x80");
  }
}
