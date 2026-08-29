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
#include <catch2/catch_test_macros.hpp>

#include <string_view>
#include <filesystem>
#include <string>

#include "LIEF/config.h"

#include "LIEF/Abstract/Binary.hpp" // IWYU pragma: keep
#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/COFF/Binary.hpp"
#include "LIEF/COFF/Parser.hpp"

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/utils.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/BinaryParser.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/Parser.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"

#if defined(LIEF_ART_SUPPORT)
  #include "LIEF/ART/File.hpp"
  #include "LIEF/ART/Parser.hpp"
#endif

#if defined(LIEF_DEX_SUPPORT)
  #include "LIEF/DEX/File.hpp"
  #include "LIEF/DEX/Parser.hpp"
#endif

#if defined(LIEF_OAT_SUPPORT)
  #include "LIEF/OAT/Binary.hpp"
  #include "LIEF/OAT/Parser.hpp"
#endif

#if defined(LIEF_VDEX_SUPPORT)
  #include "LIEF/VDEX/File.hpp"
  #include "LIEF/VDEX/Parser.hpp"
#endif

#include "utils.hpp"

namespace fs = std::filesystem;

using namespace LIEF;

template<class Fn>
void check_path_inputs(const std::string& sample, Fn&& parse) {
  REQUIRE(parse(sample.c_str()));
  REQUIRE(parse(sample));
  REQUIRE(parse(std::string_view(sample)));
  REQUIRE(parse(fs::path(sample)));
}

[[maybe_unused]]
void check_overload_resolution(const char* cstr, const std::string& str,
                               std::string_view sv, const fs::path& path) {
  (void)ELF::Parser::parse_from_dump(cstr, 0);
  (void)ELF::Parser::parse_from_dump(str, 0);
  (void)ELF::Parser::parse_from_dump(sv, 0);
  (void)ELF::Parser::parse_from_dump(path, 0);

  (void)PE::Parser::parse_from_dump(cstr, 0);
  (void)PE::Parser::parse_from_dump(str, 0);
  (void)PE::Parser::parse_from_dump(sv, 0);
  (void)PE::Parser::parse_from_dump(path, 0);

  (void)MachO::Parser::parse_from_dump(cstr, 0);
  (void)MachO::Parser::parse_from_dump(str, 0);
  (void)MachO::Parser::parse_from_dump(sv, 0);
  (void)MachO::Parser::parse_from_dump(path, 0);

  (void)MachO::BinaryParser::parse(cstr);
  (void)MachO::BinaryParser::parse(str);
  (void)MachO::BinaryParser::parse(sv);
  (void)MachO::BinaryParser::parse(path);

  (void)MachO::BinaryParser::parse(cstr, MachO::ParserConfig::deep());
  (void)MachO::BinaryParser::parse(str, MachO::ParserConfig::deep());
  (void)MachO::BinaryParser::parse(sv, MachO::ParserConfig::deep());
  (void)MachO::BinaryParser::parse(path, MachO::ParserConfig::deep());
}

TEST_CASE("lief.test.parser_api", "[lief][test][parser]") {
  SECTION("LIEF::Parser") {
    check_path_inputs(test::get_elf_sample("ELF64_x86-64_binary_ls.bin"),
                      [](const auto& file) {
                        return LIEF::Parser::parse(file) != nullptr;
                      });
  }

  SECTION("Non NUL-terminated std::string_view") {
    const std::string sample = test::get_elf_sample("ELF64_x86-64_binary_ls.bin");
    const std::string buffer = sample + "/trailing/garbage";
    const std::string_view view(buffer.data(), sample.size());

    REQUIRE(ELF::is_elf(view));
    REQUIRE(LIEF::Parser::parse(view) != nullptr);
    REQUIRE(ELF::Parser::parse(view) != nullptr);
  }

  SECTION("ELF::Parser") {
    check_path_inputs(test::get_elf_sample("ELF64_x86-64_binary_ls.bin"),
                      [](const auto& file) {
                        return ELF::Parser::parse(file) != nullptr;
                      });
  }

  SECTION("PE::Parser") {
    check_path_inputs(test::get_pe_sample("PE64_x86-64_binary_HelloWorld.exe"),
                      [](const auto& file) {
                        return PE::Parser::parse(file) != nullptr;
                      });
  }

  SECTION("MachO::Parser") {
    check_path_inputs(test::get_macho_sample("MachO64_x86-64_binary_sshd.bin"),
                      [](const auto& file) {
                        return MachO::Parser::parse(file) != nullptr;
                      });
  }

  SECTION("COFF::Parser") {
    check_path_inputs(test::get_sample("COFF", "arm64_debug_cl.obj"),
                      [](const auto& file) {
                        return COFF::Parser::parse(file) != nullptr;
                      });
  }

  SECTION("PE::SignatureParser") {
    check_path_inputs(test::get_sample("pkcs7", "cert0.p7b"),
                      [](const auto& file) {
                        return PE::SignatureParser::parse(file).has_value();
                      });
  }

#if defined(LIEF_OAT_SUPPORT)
  SECTION("OAT::Parser") {
    check_path_inputs(test::get_oat_sample("OAT_138_AArch64_xdivert.oat"),
                      [](const auto& file) {
                        return OAT::Parser::parse(file) != nullptr;
                      });
  }

  SECTION("OAT::Parser (OAT + VDEX)") {
    const std::string oat =
        test::get_oat_sample("OAT_124_x86-64_CallDeviceId.oat");
    const std::string vdex =
        test::get_sample("VDEX", "VDEX_06_x86-64_CallDeviceId.vdex");

    REQUIRE(OAT::Parser::parse(oat.c_str(), vdex.c_str()) != nullptr);
    REQUIRE(OAT::Parser::parse(oat, vdex) != nullptr);
    REQUIRE(OAT::Parser::parse(std::string_view(oat), std::string_view(vdex)) !=
            nullptr);
    REQUIRE(OAT::Parser::parse(fs::path(oat), fs::path(vdex)) != nullptr);

    REQUIRE(OAT::Parser::parse(fs::path(oat), vdex) != nullptr);
    REQUIRE(OAT::Parser::parse(oat, fs::path(vdex)) != nullptr);
  }
#endif

#if defined(LIEF_DEX_SUPPORT)
  SECTION("DEX::Parser") {
    check_path_inputs(
        test::get_sample("DEX", "DEX35_com.starbucks.mobilecard.dex"),
        [](const auto& file) { return DEX::Parser::parse(file) != nullptr; }
    );
  }
#endif

#if defined(LIEF_ART_SUPPORT)
  SECTION("ART::Parser") {
    check_path_inputs(test::get_sample("ART", "ART_017_AArch64_boot.art"),
                      [](const auto& file) {
                        return ART::Parser::parse(file) != nullptr;
                      });
  }
#endif

#if defined(LIEF_VDEX_SUPPORT)
  SECTION("VDEX::Parser") {
    check_path_inputs(test::get_sample("VDEX", "VDEX_06_AArch64_Telecom.vdex"),
                      [](const auto& file) {
                        return VDEX::Parser::parse(file) != nullptr;
                      });
  }
#endif
}
