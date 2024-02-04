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
#include <LIEF/utils.hpp>
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

}
