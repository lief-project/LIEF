/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "LIEF/hash.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include "utils.hpp"

using namespace LIEF;

TEST_CASE("lief.test.pe", "[lief][test][pe]") {
  SECTION("parser") {
    auto pe = PE::Parser::parse("/does/not/exists");
    REQUIRE(pe == nullptr);
  }
  SECTION("hash") {
    std::string path = test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
    std::unique_ptr<PE::Binary> lhs = PE::Parser::parse(path);
    std::unique_ptr<PE::Binary> rhs = PE::Parser::parse(path);
    REQUIRE(LIEF::hash(*lhs) == LIEF::hash(*rhs));
  }
  SECTION("resources_nodes") {
    using namespace PE;
    std::string path = test::get_sample("PE", "PE64_x86-64_binary_mfc-application.exe");
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
}


