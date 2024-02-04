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
#include <LIEF/enums.hpp>

enum class TEST_ENUM: uint32_t  {
  None = 0,
  A = 1 << 2,
  B = 1 << 5,

  A_or_B  = A | B,
  A_and_B = A & B,
  not_A = ~A,
};

ENABLE_BITMASK_OPERATORS(TEST_ENUM);

TEST_CASE("lief.test.enums_bitmask", "[lief][test][enums_bitmask]") {

  SECTION("operator|") {
    REQUIRE((TEST_ENUM::A | TEST_ENUM::B) == TEST_ENUM::A_or_B);
  }

  SECTION("operator&") {
    REQUIRE((TEST_ENUM::A & TEST_ENUM::B) == TEST_ENUM::A_and_B);
  }

  SECTION("operator~") {
    REQUIRE(~TEST_ENUM::A == TEST_ENUM::not_A);
  }

  SECTION("operator|=") {
    TEST_ENUM value = TEST_ENUM::A;
    REQUIRE((value |= TEST_ENUM::B) == TEST_ENUM::A_or_B);
  }

  SECTION("operator&=") {
    TEST_ENUM value = TEST_ENUM::A;
    REQUIRE((value &= TEST_ENUM::B) == TEST_ENUM::A_and_B);
  }

  SECTION("bool") {
    REQUIRE(is_true(TEST_ENUM::A));
    REQUIRE(!is_true(TEST_ENUM::None));
  }
}
