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
    }
    {
      std::string path = test::get_oat_sample("OAT_138_AArch64_xdivert.oat");
      std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse(path);
      REQUIRE(LIEF::ELF::Binary::classof(bin.get()));
    }
  }
}


