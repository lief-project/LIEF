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
#include <LIEF/hash.hpp>
#include <LIEF/ELF/Section.hpp>

using namespace LIEF;

TEST_CASE("lief.test.hash", "[lief][test][hash]") {

  SECTION("std::vector") {
    std::vector<uint8_t> buffer_1 = {1, 2, 3, 4};
    std::vector<uint8_t> buffer_2 = {1, 2, 3, 4};
    REQUIRE(hash(buffer_1) == hash(buffer_2));
  }

  SECTION("span") {
    std::vector<uint8_t> buffer_1 = {1, 2, 3, 4};
    std::vector<uint8_t> buffer_2 = {1, 2, 3, 4};

    const span<const uint8_t> S1 = buffer_1;
    const span<const uint8_t> S2 = buffer_2;

    REQUIRE(hash(S1) == hash(S2));
  }

  SECTION("LIEF::Object") {
    ELF::Section S1(".hello");
    ELF::Section S2(".hello");

    REQUIRE(hash(S1) == hash(S2));
  }


  SECTION("LIEF::Hash::pair") {
    Hash H1(0x123);
    Hash H2(0x123);

    auto P1 = std::make_pair(1, 2);
    auto P2 = std::make_pair(1, 2);

    REQUIRE(H1.process(P1).value() == H2.process(P2).value());
  }
}
