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
#include "LIEF/MachO/BuildVersion.hpp"
#include "LIEF/MachO/BuildToolVersion.hpp"
#include "LIEF/MachO/MainCommand.hpp"
#include "LIEF/MachO/DylinkerCommand.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/DataCodeEntry.hpp"
#include "LIEF/MachO/DyldChainedFormat.hpp"
#include "LIEF/MachO/Header.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/MachO/RPathCommand.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/EnumToString.hpp"

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

#include "utils.hpp"

using namespace LIEF;
using namespace std::string_literals;

std::unique_ptr<MachO::Binary> reload(MachO::Binary& bin) {
  std::ostringstream oss;
  bin.write(oss);
  std::string buffer = oss.str();

  auto stream =
      std::make_unique<SpanStream>((const uint8_t*)buffer.data(), buffer.size());
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

  SECTION("BuildVersion") {
    // Test the explicit constructor (platform, minos, sdk, tools)
    MachO::BuildVersion::version_t minos = {14, 0, 0};
    MachO::BuildVersion::version_t sdk = {14, 2, 0};
    MachO::BuildVersion::tools_list_t tools;
    MachO::BuildVersion bv(MachO::BuildVersion::PLATFORMS::MACOS, minos, sdk,
                           tools);

    CHECK(bv.platform() == MachO::BuildVersion::PLATFORMS::MACOS);
    CHECK(bv.minos() == minos);
    CHECK(bv.sdk() == sdk);
    CHECK(bv.tools().empty());

    // Test the print() method
    {
      std::ostringstream oss;
      bv.print(oss);
      std::string output = oss.str();
      CHECK_THAT(output, Catch::Matchers::ContainsSubstring("MACOS"));
      CHECK_THAT(output, Catch::Matchers::ContainsSubstring("14.0.0"));
      CHECK_THAT(output, Catch::Matchers::ContainsSubstring("14.2.0"));
    }

    // Test to_string with invalid enum value (covers fallback "UNKNOWN")
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::BuildVersion::PLATFORMS>(9999))
          ) == "UNKNOWN");
  }

  SECTION("MainCommand") {
    MachO::MainCommand main_cmd(0x1234, 0x8000);
    CHECK(main_cmd.entrypoint() == 0x1234);
    CHECK(main_cmd.stack_size() == 0x8000);

    std::ostringstream oss;
    main_cmd.print(oss);
    CHECK_THAT(oss.str(), Catch::Matchers::ContainsSubstring("0x1234"));
  }

  SECTION("DylinkerCommand") {
    MachO::DylinkerCommand dylinker("/usr/lib/dyld");
    CHECK(dylinker.name() == "/usr/lib/dyld");

    std::ostringstream oss;
    dylinker.print(oss);
    CHECK_THAT(oss.str(), Catch::Matchers::ContainsSubstring("/usr/lib/dyld"));
  }

  SECTION("DynamicSymbolCommand") {
    MachO::DynamicSymbolCommand dyscmd;
    CHECK(dyscmd.command() == MachO::LoadCommand::TYPE::DYSYMTAB);

    std::ostringstream oss;
    dyscmd.print(oss);
    CHECK_THAT(oss.str(), Catch::Matchers::ContainsSubstring("local symbol"));
  }

  SECTION("DylibCommand-factories") {
    auto reexport = MachO::DylibCommand::reexport_dylib("/usr/lib/libfoo.dylib");
    CHECK(reexport.command() == MachO::LoadCommand::TYPE::REEXPORT_DYLIB);
    CHECK(reexport.name() == "/usr/lib/libfoo.dylib");

    auto upward = MachO::DylibCommand::load_upward_dylib("/usr/lib/libbar.dylib");
    CHECK(upward.command() == MachO::LoadCommand::TYPE::LOAD_UPWARD_DYLIB);

    auto lazy = MachO::DylibCommand::lazy_load_dylib("/usr/lib/libbaz.dylib");
    CHECK(lazy.command() == MachO::LoadCommand::TYPE::LAZY_LOAD_DYLIB);
  }

  SECTION("RPathCommand") {
    MachO::RPathCommand rpath("@executable_path/../Frameworks");
    CHECK(rpath.path() == "@executable_path/../Frameworks");
    CHECK(rpath.command() == MachO::LoadCommand::TYPE::RPATH);
    CHECK(rpath.size() > 0);
  }

  SECTION("LoadCommand-is_linkedit_data") {
    // Use sshd for DyldInfo, DynamicSymbolCommand, FunctionStarts,
    // DataInCode, CodeSignature, SymbolCommand
    {
      std::string path = test::get_macho_sample("MachO64_x86-64_binary_sshd.bin");
      auto bin = MachO::Parser::parse(path)->take(0);
      REQUIRE(bin != nullptr);
      size_t linkedit_count = 0;
      for (const auto& cmd : bin->commands()) {
        if (MachO::LoadCommand::is_linkedit_data(cmd)) {
          linkedit_count++;
        }
      }
      CHECK(linkedit_count >= 5);
    }
    // Use crypt_and_hash for DyldExportsTrie, DyldChainedFixups
    {
      std::string path = test::get_macho_sample(
          "9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_"
          "crypt_and_hash.macho"
      );
      auto fat = MachO::Parser::parse(path);
      REQUIRE(fat != nullptr);
      auto bin = fat->take(MachO::Header::CPU_TYPE::ARM64);
      REQUIRE(bin != nullptr);
      size_t linkedit_count = 0;
      for (const auto& cmd : bin->commands()) {
        if (MachO::LoadCommand::is_linkedit_data(cmd)) {
          linkedit_count++;
        }
      }
      CHECK(linkedit_count >= 6);
    }
    // Use libdyld for SegmentSplitInfo
    {
      std::string path =
          test::get_macho_sample("FAT_MachO_x86_x86-64_library_libdyld.dylib");
      auto fat = MachO::Parser::parse(path);
      REQUIRE(fat != nullptr);
      auto bin = fat->take(1);
      REQUIRE(bin != nullptr);
      bool found_ssi = false;
      for (const auto& cmd : bin->commands()) {
        if (MachO::LoadCommand::is_linkedit_data(cmd) &&
            cmd.command() == MachO::LoadCommand::TYPE::SEGMENT_SPLIT_INFO)
        {
          found_ssi = true;
        }
      }
      CHECK(found_ssi);
    }
  }

  SECTION("to_string-fallbacks") {
    // BuildToolVersion: invalid TOOLS enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::BuildToolVersion::TOOLS>(9999))
          ) == "UNKNOWN");

    // DataCodeEntry: invalid TYPES enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::DataCodeEntry::TYPES>(9999))
          ) == "UNKNOWN");

    // DYLD_CHAINED_FORMAT: invalid enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::DYLD_CHAINED_FORMAT>(9999))
          ) == "UNKNOWN");

    // DYLD_CHAINED_PTR_FORMAT: invalid enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::DYLD_CHAINED_PTR_FORMAT>(9999))
          ) == "UNKNOWN");

    // Header::FLAGS: invalid enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::Header::FLAGS>(0x40000000))
          ) == "UNKNOWN");

    // Header::FILE_TYPE: invalid enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::Header::FILE_TYPE>(9999))
          ) == "UNKNOWN");

    // Header::CPU_TYPE: invalid enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::Header::CPU_TYPE>(9999))
          ) == "UNKNOWN");

    // LoadCommand::TYPE: invalid enum
    CHECK(std::string(
              MachO::to_string(static_cast<MachO::LoadCommand::TYPE>(0xFFFFFFFF))
          ) == "UNKNOWN");
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
              .add_binding(__auth_got + 0 * sizeof(uint64_t), "_calloc")
              .add_relocation(__auth_got + 2 * sizeof(uint64_t),
                              bin->imagebase() + 0xdeadc0de)
              .add_binding(__auth_got + 4 * sizeof(uint64_t), "_dlopen")
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
