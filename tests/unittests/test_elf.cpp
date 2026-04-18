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
#include <catch2/matchers/catch_matchers_string.hpp>

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"
#include "LIEF/ELF/EnumToString.hpp"
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


      CHECK(bin->get_int_from_virtual_address<uint8_t>(0x5531).value_or(0) ==
            0xC6);
      CHECK(bin->get_int_from_virtual_address<uint16_t>(0xAE7A).value_or(0) ==
            0x58e4);
      CHECK(bin->get_int_from_virtual_address<uint32_t>(0xAF3C).value_or(0) ==
            0x11eb9);
      CHECK(bin->get_int_from_virtual_address<uint64_t>(0xAEF6).value_or(0) ==
            0xd1042803bdf82001);
    }
    {
      std::string path = test::get_oat_sample("OAT_138_AArch64_xdivert.oat");
      std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse(path);
      REQUIRE(LIEF::ELF::Binary::classof(bin.get()));
    }
  }

  SECTION("DynamicEntryArray") {
    ELF::DynamicEntryArray arr(ELF::DynamicEntry::TAG::INIT_ARRAY,
                               {0x1000, 0x2000, 0x3000});
    CHECK(arr.size() == 3);
    CHECK(arr[0] == 0x1000);
    CHECK(arr[2] == 0x3000);

    // Test remove
    arr.remove(0x2000);
    CHECK(arr.size() == 2);

    // Test insert
    arr.insert(1, 0x1500);
    CHECK(arr.size() == 3);
    CHECK(arr[1] == 0x1500);

    // Test print
    std::ostringstream oss;
    arr.print(oss);
    CHECK_THAT(oss.str(), Catch::Matchers::ContainsSubstring("0x1000"));
  }

  SECTION("DynamicEntryRpath") {
    ELF::DynamicEntryRpath rpath("/usr/lib:/opt/lib");
    CHECK(rpath.rpath() == "/usr/lib:/opt/lib");

    auto paths = rpath.paths();
    CHECK(paths.size() == 2);
    CHECK(paths[0] == "/usr/lib");
    CHECK(paths[1] == "/opt/lib");

    // Test append
    rpath.append("/home/lib");
    CHECK(rpath.paths().size() == 3);

    // Test remove
    rpath.remove("/opt/lib");
    CHECK(rpath.paths().size() == 2);

    // Test insert
    rpath.insert(0, "/first/lib");
    CHECK(rpath.paths()[0] == "/first/lib");

    // Test print
    std::ostringstream oss;
    rpath.print(oss);
    CHECK(oss.str().find("/first/lib") != std::string::npos);
  }

  SECTION("DynamicEntry-create") {
    // Test DynamicEntry::create for various tags
    auto needed = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::NEEDED, 0);
    CHECK(needed != nullptr);

    auto soname = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::SONAME, 0);
    CHECK(soname != nullptr);

    auto aux = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::AUXILIARY, 0);
    CHECK(aux != nullptr);

    auto filter = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::FILTER, 0);
    CHECK(filter != nullptr);

    auto runpath = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::RUNPATH, 0);
    CHECK(runpath != nullptr);

    auto rpath_e = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::RPATH, 0);
    CHECK(rpath_e != nullptr);

    auto flags1 = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::FLAGS_1, 1);
    CHECK(flags1 != nullptr);

    auto flags = ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::FLAGS, 1);
    CHECK(flags != nullptr);

    auto init_arr =
        ELF::DynamicEntry::create(ELF::DynamicEntry::TAG::INIT_ARRAY, 0);
    CHECK(init_arr != nullptr);

    // Test to_string for DynamicEntry::TAG
    CHECK(std::string(ELF::to_string(ELF::DynamicEntry::TAG::NEEDED)) == "NEEDED");
    CHECK(std::string(ELF::to_string(ELF::DynamicEntry::TAG::UNKNOWN)) ==
          "UNKNOWN");
  }

  SECTION("DynamicEntry-to_value") {
    // Test round-trip for AUXILIARY and FILTER (special tags)
    CHECK(ELF::DynamicEntry::to_value(ELF::DynamicEntry::TAG::AUXILIARY) ==
          static_cast<uint64_t>(ELF::DynamicEntry::TAG::AUXILIARY));
    CHECK(ELF::DynamicEntry::to_value(ELF::DynamicEntry::TAG::FILTER) ==
          static_cast<uint64_t>(ELF::DynamicEntry::TAG::FILTER));
  }

  SECTION("SymbolVersion-operator<<") {
    std::string path = test::get_elf_sample("ELF64_x86-64_binary_ls.bin");
    auto bin = ELF::Parser::parse(path);
    REQUIRE(bin != nullptr);

    for (const auto& sym : bin->dynamic_symbols()) {
      const ELF::SymbolVersion* sv = sym.symbol_version();
      if (sv != nullptr) {
        std::ostringstream oss;
        oss << *sv;
        CHECK(!oss.str().empty());
      }
    }

    // Test SymbolVersionDefinition str
    for (const auto& svd : bin->symbols_version_definition()) {
      std::ostringstream oss;
      oss << svd;
      CHECK(!oss.str().empty());
    }
  }

  SECTION("Header-to_string-fallbacks") {
    CHECK(std::string(
              ELF::to_string(static_cast<ELF::Header::FILE_TYPE>(0xFFFF))
          ) == "UNKNOWN");
    CHECK(std::string(ELF::to_string(static_cast<ELF::Header::VERSION>(0xFFFF))) ==
          "UNKNOWN");
    CHECK(std::string(ELF::to_string(static_cast<ELF::Header::CLASS>(0xFF))) ==
          "UNKNOWN");
    CHECK(std::string(ELF::to_string(static_cast<ELF::Header::OS_ABI>(0xFE))) ==
          "UNKNOWN");
    CHECK(std::string(ELF::to_string(static_cast<ELF::Header::ELF_DATA>(0xFF))) ==
          "UNKNOWN");
  }

  SECTION("NoteAbi-to_string-fallback") {
    CHECK(std::string(ELF::to_string(static_cast<ELF::NoteAbi::ABI>(0xFF))) ==
          "UNKNOWN");
  }

  SECTION("DynamicEntryFlags-to_string-fallback") {
    CHECK(std::string(
              ELF::to_string(static_cast<ELF::DynamicEntryFlags::FLAG>(0xDEAD))
          ) == "UNKNOWN");
  }
}
