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

#include <algorithm>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/CodeIntegrity.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/DelayImport.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/ParserConfig.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/debug/CodeViewPDB.hpp"
#include "LIEF/PE/debug/Debug.hpp"
#include "LIEF/PE/debug/ExDllCharacteristics.hpp"
#include "LIEF/PE/debug/FPO.hpp"
#include "LIEF/PE/debug/PDBChecksum.hpp"
#include "LIEF/PE/debug/Pogo.hpp"
#include "LIEF/PE/debug/Repro.hpp"
#include "LIEF/hash.hpp"

#include "utils.hpp"

using namespace LIEF;
using namespace std::string_literals;
using Catch::Matchers::Equals;

namespace {

/// Build a PE32 file whose section headers all point to the same raw data.
std::vector<uint8_t> build_overlapping_sections_pe(uint32_t nb_sections,
                                                   uint32_t file_size) {
  static constexpr uint32_t ALIGNMENT = 0x1000;
  static constexpr uint32_t OPTIONAL_SIZE = 0xE0;
  static constexpr uint32_t PE_OFFSET = 0x40;
  static constexpr uint32_t COFF_OFFSET = PE_OFFSET + 4;
  static constexpr uint32_t OPTIONAL_OFFSET = COFF_OFFSET + 20;
  static constexpr uint32_t SECTIONS_OFFSET = OPTIONAL_OFFSET + OPTIONAL_SIZE;
  static constexpr uint32_t SECTION_SIZE = 40;

  const uint64_t span =
      (uint64_t{file_size} + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT;
  const uint64_t sections_end = SECTIONS_OFFSET + nb_sections * SECTION_SIZE;
  assert(sections_end <= file_size);

  std::vector<uint8_t> raw(file_size, 0xCC);
  std::fill(raw.begin(), raw.begin() + sections_end, 0);

  const auto write16 = [&raw](size_t offset, uint16_t value) {
    std::memcpy(raw.data() + offset, &value, sizeof(value));
  };
  const auto write32 = [&raw](size_t offset, uint32_t value) {
    std::memcpy(raw.data() + offset, &value, sizeof(value));
  };

  raw[0] = 'M';
  raw[1] = 'Z';
  write32(0x3C, PE_OFFSET);
  std::memcpy(raw.data() + PE_OFFSET, "PE\0\0", 4);

  // COFF header
  write16(COFF_OFFSET + 0, 0x14C);   // Machine (i386)
  write16(COFF_OFFSET + 2, nb_sections);
  write16(COFF_OFFSET + 16, OPTIONAL_SIZE);
  write16(COFF_OFFSET + 18, 0x0102);

  // PE32 optional header
  write16(OPTIONAL_OFFSET + 0, 0x10B);
  write32(OPTIONAL_OFFSET + 28, 0x400000);  // ImageBase
  write32(OPTIONAL_OFFSET + 32, ALIGNMENT); // SectionAlignment
  write32(OPTIONAL_OFFSET + 36, 0x200);     // FileAlignment
  write32(OPTIONAL_OFFSET + 56,
          static_cast<uint32_t>(ALIGNMENT + nb_sections * span));
  write32(OPTIONAL_OFFSET + 60, static_cast<uint32_t>(sections_end));
  write16(OPTIONAL_OFFSET + 68, 3);  // Subsystem: console
  write32(OPTIONAL_OFFSET + 92, 16); // NumberOfRvaAndSizes

  for (uint32_t i = 0; i < nb_sections; ++i) {
    const size_t header = SECTIONS_OFFSET + i * SECTION_SIZE;
    const std::string name = ".s" + std::to_string(i);
    std::memcpy(raw.data() + header, name.data(),
                std::min<size_t>(name.size(), 8));
    write32(header + 8, file_size);   // VirtualSize
    write32(header + 12,
            static_cast<uint32_t>(ALIGNMENT + i * span)); // VirtualAddress
    write32(header + 16, file_size);  // SizeOfRawData
    write32(header + 20, 0);          // PointerToRawData
    write32(header + 36, 0x40000040); // MEM_READ | CNT_INITIALIZED_DATA
  }

  return raw;
}

}

TEST_CASE("lief.test.pe", "[lief][test][pe]") {
  SECTION("parser") {
    auto pe = PE::Parser::parse("/does/not/exists");
    REQUIRE(pe == nullptr);
  }
  SECTION("hash") {
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<PE::Binary> lhs = PE::Parser::parse(path);
    std::unique_ptr<PE::Binary> rhs = PE::Parser::parse(path);
    REQUIRE(LIEF::hash(*lhs) == LIEF::hash(*rhs));
  }
  SECTION("resources_nodes") {
    using namespace PE;
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<PE::Binary> bin = PE::Parser::parse(path);
    ResourceNode* node = bin->resources();
    REQUIRE(ResourceDirectory::classof(node));
    auto clone = std::unique_ptr<ResourceNode>(node->clone());
    REQUIRE(*clone == *node);

    ResourceNode* current = node;
    while (!ResourceData::classof(current)) {
      if (current->childs().empty()) {
        break;
      }
      for (ResourceNode& child : current->childs()) {
        current = &child;
        break;
      }
    }
    REQUIRE(current != node);
    REQUIRE(current->is_data());
    {
      auto& data_node = static_cast<ResourceData&>(*current);
      auto clone = std::unique_ptr<ResourceNode>(data_node.clone());
      REQUIRE(*clone == data_node);
    }
  }

  SECTION("debug") {
    PE::Debug Wrong(static_cast<PE::Debug::TYPES>(-1));
    REQUIRE_THAT(to_string(Wrong.type()), Equals("UNKNOWN"));

    REQUIRE(!PE::CodeView::classof(&Wrong));
    REQUIRE(!PE::Pogo::classof(&Wrong));

    PE::CodeView CV(PE::CodeView::SIGNATURES::CV_50);
    REQUIRE(PE::CodeView::classof(&CV));
    REQUIRE(!PE::CodeViewPDB::classof(&CV));
    {
      PE::Pogo Default;
      REQUIRE(PE::Pogo::classof(&Default));

      PE::Pogo PG(PE::Pogo::SIGNATURES::UNKNOWN);
      REQUIRE(!PE::CodeViewPDB::classof(&PG));
      REQUIRE(PE::Pogo::classof(&PG));
    }

    PE::Repro repro;
    REQUIRE(PE::Repro::classof(&repro));
  }

  SECTION("classof") {
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<LIEF::Binary> pe = LIEF::Parser::parse(path);
    REQUIRE(LIEF::PE::Binary::classof(pe.get()));
  }

  SECTION("to_string-coverage") {
    // FPO::FRAME_TYPE to_string
    CHECK(std::string(PE::to_string(PE::FPO::FRAME_TYPE::FPO)) == "FPO");
    CHECK(std::string(PE::to_string(PE::FPO::FRAME_TYPE::TRAP)) == "TRAP");
    CHECK(std::string(PE::to_string(PE::FPO::FRAME_TYPE::TSS)) == "TSS");
    CHECK(std::string(PE::to_string(PE::FPO::FRAME_TYPE::NON_FPO)) == "NON_FPO");
    CHECK(std::string(PE::to_string(static_cast<PE::FPO::FRAME_TYPE>(0xFF))) ==
          "UNKNOWN");

    // PDBChecksum::HASH_ALGO to_string
    CHECK(std::string(PE::to_string(PE::PDBChecksum::HASH_ALGO::SHA256)) ==
          "SHA256");
    CHECK(std::string(
              PE::to_string(static_cast<PE::PDBChecksum::HASH_ALGO>(0xFF))
          ) == "UNKNOWN");

    // ExDllCharacteristics::CHARACTERISTICS to_string
    CHECK(std::string(
              PE::to_string(PE::ExDllCharacteristics::CHARACTERISTICS::CET_COMPAT)
          ) == "CET_COMPAT");
    CHECK(std::string(PE::to_string(
              static_cast<PE::ExDllCharacteristics::CHARACTERISTICS>(0xDEAD)
          )) == "UNKNOWN");

    // ParserConfig to_string
    PE::ParserConfig cfg;
    std::ostringstream oss;
    oss << cfg;
    CHECK(!oss.str().empty());
  }

  SECTION("str-coverage") {
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    auto bin = PE::Parser::parse(path);
    REQUIRE(bin != nullptr);

    // Export str
    if (auto* exp = bin->get_export()) {
      std::ostringstream oss;
      oss << *exp;
      CHECK(!oss.str().empty());

      for (const auto& entry : exp->entries()) {
        std::ostringstream oss2;
        oss2 << entry;
        CHECK(!oss2.str().empty());
        break;
      }
    }

    // Import str
    for (const auto& imp : bin->imports()) {
      std::ostringstream oss;
      oss << imp;
      CHECK(!oss.str().empty());

      for (const auto& entry : imp.entries()) {
        std::ostringstream oss2;
        oss2 << entry;
        CHECK(!oss2.str().empty());
        break;
      }
      break;
    }

    // Section str
    for (const auto& sec : bin->sections()) {
      std::ostringstream oss;
      oss << sec;
      CHECK(!oss.str().empty());
      break;
    }

    // Relocation / RelocationEntry str
    for (const auto& reloc : bin->relocations()) {
      std::ostringstream oss;
      oss << reloc;
      CHECK(!oss.str().empty());

      for (const auto& entry : reloc.entries()) {
        std::ostringstream oss2;
        oss2 << entry;
        CHECK(!oss2.str().empty());
        break;
      }
      break;
    }

    // DataDirectory str
    for (const auto& dir : bin->data_directories()) {
      std::ostringstream oss;
      oss << dir;
      CHECK(!oss.str().empty());
      break;
    }

    // Debug str
    for (const auto& dbg : bin->debug()) {
      std::ostringstream oss;
      oss << dbg;
      CHECK(!oss.str().empty());
      break;
    }

    // CodeIntegrity
    {
      PE::CodeIntegrity ci;
      std::ostringstream oss;
      oss << ci;
      CHECK(!oss.str().empty());
    }
  }
}

TEST_CASE("lief.test.pe.overlapping_sections",
          "[lief][test][pe][overlapping]") {
  static constexpr uint32_t NB_SECTIONS = 1000;
  static constexpr uint32_t FILE_SIZE = 0x10000;
  std::vector<uint8_t> raw =
      build_overlapping_sections_pe(NB_SECTIONS, FILE_SIZE);
  std::unique_ptr<PE::Binary> bin = PE::Parser::parse(raw);
  REQUIRE(bin != nullptr);

  auto sections = bin->sections();
  REQUIRE(sections.size() == NB_SECTIONS);

  auto it = sections.begin();
  REQUIRE(it != sections.end());
  const PE::Section& first = *it;
  const span<const uint8_t> reference = first.content();
  REQUIRE(reference.size() == FILE_SIZE);
  REQUIRE(std::memcmp(reference.data(), raw.data(), FILE_SIZE) == 0);

  for (const PE::Section& section : sections) {
    REQUIRE(section.content().size() == FILE_SIZE);
    REQUIRE(section.content().data() == reference.data());
  }

  // The content is shared until one section is modified (copy-on-write).
  ++it;
  REQUIRE(it != sections.end());
  PE::Section& second = *it;
  span<uint8_t> writable = second.writable_content();
  REQUIRE(writable.size() == FILE_SIZE);
  writable[0] ^= 0xFF;

  REQUIRE(first.content()[0] == raw[0]);
  REQUIRE(second.content()[0] == (raw[0] ^ 0xFF));
}
