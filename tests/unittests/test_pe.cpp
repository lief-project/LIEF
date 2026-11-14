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
#include <catch2/matchers/catch_matchers_string.hpp>

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

TEST_CASE("lief.test.pe", "[lief][test][pe]") {
  SECTION("parser") {
    auto pe = PE::Parser::parse("/does/not/exists");
    CHECK(pe == nullptr);
  }
  SECTION("hash") {
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<PE::Binary> lhs = PE::Parser::parse(path);
    std::unique_ptr<PE::Binary> rhs = PE::Parser::parse(path);
    CHECK(LIEF::hash(*lhs) == LIEF::hash(*rhs));
  }
  SECTION("resources_nodes") {
    using namespace PE;
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<PE::Binary> bin = PE::Parser::parse(path);
    ResourceNode* node = bin->resources();
    REQUIRE(ResourceDirectory::classof(node));
    auto clone = std::unique_ptr<ResourceNode>(node->clone());
    CHECK(*clone == *node);

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
      CHECK(*clone == data_node);
    }
  }

  SECTION("debug") {
    PE::Debug Wrong(static_cast<PE::Debug::TYPES>(-1));
    CHECK_THAT(to_string(Wrong.type()), Equals("UNKNOWN"));

    CHECK_FALSE(PE::CodeView::classof(&Wrong));
    CHECK_FALSE(PE::Pogo::classof(&Wrong));

    PE::CodeView CV(PE::CodeView::SIGNATURES::CV_50);
    CHECK(PE::CodeView::classof(&CV));
    CHECK_FALSE(PE::CodeViewPDB::classof(&CV));
    {
      PE::Pogo Default;
      CHECK(PE::Pogo::classof(&Default));

      PE::Pogo PG(PE::Pogo::SIGNATURES::UNKNOWN);
      CHECK_FALSE(PE::CodeViewPDB::classof(&PG));
      CHECK(PE::Pogo::classof(&PG));
    }

    PE::Repro repro;
    CHECK(PE::Repro::classof(&repro));
  }

  SECTION("classof") {
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<LIEF::Binary> pe = LIEF::Parser::parse(path);
    CHECK(LIEF::PE::Binary::classof(pe.get()));
  }

  SECTION("to_string-coverage") {
    // FPO::FRAME_TYPE to_string
    CHECK_THAT(PE::to_string(PE::FPO::FRAME_TYPE::FPO), Equals("FPO"));
    CHECK_THAT(PE::to_string(PE::FPO::FRAME_TYPE::TRAP), Equals("TRAP"));
    CHECK_THAT(PE::to_string(PE::FPO::FRAME_TYPE::TSS), Equals("TSS"));
    CHECK_THAT(PE::to_string(PE::FPO::FRAME_TYPE::NON_FPO), Equals("NON_FPO"));
    CHECK_THAT(PE::to_string(static_cast<PE::FPO::FRAME_TYPE>(0xFF)),
               Equals("UNKNOWN"));

    // PDBChecksum::HASH_ALGO to_string
    CHECK_THAT(PE::to_string(PE::PDBChecksum::HASH_ALGO::SHA256),
               Equals("SHA256"));
    CHECK_THAT(PE::to_string(static_cast<PE::PDBChecksum::HASH_ALGO>(0xFF)),
               Equals("UNKNOWN"));

    // ExDllCharacteristics::CHARACTERISTICS to_string
    CHECK_THAT(
        PE::to_string(PE::ExDllCharacteristics::CHARACTERISTICS::CET_COMPAT),
        Equals("CET_COMPAT")
    );
    CHECK_THAT(PE::to_string(
                   static_cast<PE::ExDllCharacteristics::CHARACTERISTICS>(0xDEAD)
               ),
               Equals("UNKNOWN"));

    // ParserConfig to_string
    PE::ParserConfig cfg;
    std::ostringstream oss;
    oss << cfg;
    CHECK_FALSE(oss.str().empty());
  }

  SECTION("str-coverage") {
    std::string path =
        test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    auto bin = PE::Parser::parse(path);
    REQUIRE(bin != nullptr);

    SECTION("Export") {
      auto dll = PE::Parser::parse(
          test::get_pe_sample("PE64_x86-64_library_libLIEF.dll")
      );
      REQUIRE(dll != nullptr);
      const PE::Export* exp = dll->get_export();
      REQUIRE(exp != nullptr);
      REQUIRE_FALSE(exp->entries().empty());

      std::ostringstream oss;
      oss << *exp;
      CHECK_FALSE(oss.str().empty());

      std::ostringstream oss2;
      oss2 << exp->entries()[0];
      CHECK_FALSE(oss2.str().empty());
    }

    SECTION("Import") {
      REQUIRE_FALSE(bin->imports().empty());
      const PE::Import& imp = bin->imports()[0];
      REQUIRE_FALSE(imp.entries().empty());

      std::ostringstream oss;
      oss << imp;
      CHECK_FALSE(oss.str().empty());

      std::ostringstream oss2;
      oss2 << imp.entries()[0];
      CHECK_FALSE(oss2.str().empty());
    }

    SECTION("Section") {
      REQUIRE_FALSE(bin->sections().empty());
      std::ostringstream oss;
      oss << bin->sections()[0];
      CHECK_FALSE(oss.str().empty());
    }

    SECTION("Relocation") {
      REQUIRE_FALSE(bin->relocations().empty());
      const PE::Relocation& reloc = bin->relocations()[0];
      REQUIRE_FALSE(reloc.entries().empty());

      std::ostringstream oss;
      oss << reloc;
      CHECK_FALSE(oss.str().empty());

      std::ostringstream oss2;
      oss2 << reloc.entries()[0];
      CHECK_FALSE(oss2.str().empty());
    }

    SECTION("DataDirectory") {
      REQUIRE_FALSE(bin->data_directories().empty());
      std::ostringstream oss;
      oss << bin->data_directories()[0];
      CHECK_FALSE(oss.str().empty());
    }

    SECTION("Debug") {
      REQUIRE_FALSE(bin->debug().empty());
      std::ostringstream oss;
      oss << bin->debug()[0];
      CHECK_FALSE(oss.str().empty());
    }

    SECTION("CodeIntegrity") {
      PE::CodeIntegrity ci;
      std::ostringstream oss;
      oss << ci;
      CHECK_FALSE(oss.str().empty());
    }
  }
}
