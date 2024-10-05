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

#include "LIEF/logging.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/RelocationFixup.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/DyldChainedFixupsCreator.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/ChainedBindingInfo.hpp"
#include "LIEF/MachO/DyldChainedFixups.hpp"

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

#include "utils.hpp"

using namespace LIEF;
using namespace std::string_literals;

std::unique_ptr<MachO::Binary> reload(MachO::Binary& bin) {
  std::ostringstream oss;
  bin.write(oss);
  std::string buffer = std::move(oss.str());

  auto stream = std::make_unique<SpanStream>((const uint8_t*)buffer.data(), buffer.size());
  return MachO::Parser::parse(std::move(stream))->take(0);
}

TEST_CASE("lief.test.macho", "[lief][test][macho]") {
  SECTION("classof") {
    {
      std::string path = test::get_macho_sample("alivcffmpeg_armv7.dylib");
      std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse(path);
      REQUIRE(LIEF::MachO::Binary::classof(bin.get()));
    }
  }

  SECTION("DyldChainedFixupsCreator") {
    {
      SECTION("Simple Imports") {
        std::string path = test::get_macho_sample("liblog_srp.dylib");
        std::unique_ptr<MachO::Binary> bin = MachO::Parser::parse(path)->take(0);
        REQUIRE(bin != nullptr);

        uint64_t __auth_got = bin->get_section("__auth_got")->virtual_address();
        MachO::DyldChainedFixupsCreator()
          .add_binding(__auth_got + 0 * sizeof(uint64_t), "_calloc")
          .add_binding(__auth_got + 4 * sizeof(uint64_t), "_dlopen")
          .create(*bin);
        std::unique_ptr<MachO::Binary> new_bin = reload(*bin);
        const MachO::DyldChainedFixups* fixups = new_bin->dyld_chained_fixups();
        REQUIRE(fixups != nullptr);
        auto bindings = fixups->bindings();
        REQUIRE(bindings.size() == 2);
        CHECK(bindings[0].address() == __auth_got);
        CHECK(bindings[0].symbol()->name() == "_calloc");
        CHECK(bindings[0].library()->name() == "/usr/lib/libSystem.B.dylib");

        CHECK(bindings[1].address() == __auth_got + 4 * sizeof(uint64_t));
        CHECK(bindings[1].symbol()->name() == "_dlopen");
        CHECK(bindings[1].library()->name() == "/usr/lib/libSystem.B.dylib");
      }

      SECTION("Imports with relocations") {
        std::string path = test::get_macho_sample("liblog_srp.dylib");
        std::unique_ptr<MachO::Binary> bin = MachO::Parser::parse(path)->take(0);
        REQUIRE(bin != nullptr);

        uint64_t __auth_got = bin->get_section("__auth_got")->virtual_address();
        {
          logging::Scoped Scope(logging::LEVEL::WARN);
          MachO::DyldChainedFixupsCreator()
            .add_binding   (__auth_got + 0 * sizeof(uint64_t), "_calloc")
            .add_relocation(__auth_got + 2 * sizeof(uint64_t), bin->imagebase() + 0xdeadc0de)
            .add_binding   (__auth_got + 4 * sizeof(uint64_t), "_dlopen")
            .create(*bin);
        }
        std::unique_ptr<MachO::Binary> new_bin = reload(*bin);
        const MachO::DyldChainedFixups* fixups = new_bin->dyld_chained_fixups();
        REQUIRE(fixups != nullptr);
        auto bindings = fixups->bindings();
        REQUIRE(bindings.size() == 2);
        CHECK(bindings[0].address() == __auth_got);
        CHECK(bindings[0].symbol()->name() == "_calloc");
        CHECK(bindings[0].library()->name() == "/usr/lib/libSystem.B.dylib");

        CHECK(bindings[1].address() == __auth_got + 4 * sizeof(uint64_t));
        CHECK(bindings[1].symbol()->name() == "_dlopen");
        CHECK(bindings[1].library()->name() == "/usr/lib/libSystem.B.dylib");
        auto relocations = new_bin->relocations();
        REQUIRE(relocations.size() == 1);
        auto& fixup = static_cast<const MachO::RelocationFixup&>(relocations[0]);

        CHECK(fixup.address() == __auth_got + 2 * sizeof(uint64_t));
        CHECK(fixup.target() - new_bin->imagebase() == 0xdeadc0de);
      }
    }
  }
}


