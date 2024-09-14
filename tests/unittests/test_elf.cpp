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
#include <catch2/matchers/catch_matchers_string.hpp>

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/Abstract/Parser.hpp"

#include "utils.hpp"

using namespace LIEF;
using namespace std::string_literals;

TEST_CASE("lief.test.elf", "[lief][test][elf]") {
  SECTION("classof") {
    {
      std::string path = test::get_elf_sample("ELF32_ARM_binary_ls.bin");
      std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse(path);
      REQUIRE(LIEF::ELF::Binary::classof(bin.get()));


      CHECK(bin->get_int_from_virtual_address<uint8_t>(0x5531).value_or(0) == 0xC6);
      CHECK(bin->get_int_from_virtual_address<uint16_t>(0xAE7A).value_or(0) == 0x58e4);
      CHECK(bin->get_int_from_virtual_address<uint32_t>(0xAF3C).value_or(0) == 0x11eb9);
      CHECK(bin->get_int_from_virtual_address<uint64_t>(0xAEF6).value_or(0) == 0xd1042803bdf82001);
    }
    {
      std::string path = test::get_oat_sample("OAT_138_AArch64_xdivert.oat");
      std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse(path);
      REQUIRE(LIEF::ELF::Binary::classof(bin.get()));
    }
  }
}


