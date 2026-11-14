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
#include <dlfcn.h>

#include <cstring>
#include <sstream>
#include <vector>

#include "LIEF/runtime/linux/Host.hpp"
#include "LIEF/runtime/linux/Module.hpp"

using namespace LIEF;
using namespace LIEF::runtime::Linux;
using namespace std::string_literals;

TEST_CASE("lief.test.runtime.linux", "[lief][test][runtime][linux]") {
  SECTION("handle") {
    // This test ensures that LIEF can instantiate a Module from an opaque dlopen
    // handler
    void* H = dlopen("librt.so.1", RTLD_NOW);
    REQUIRE(H != nullptr);
    std::unique_ptr<Module> module = Module::from_handle(H);
    REQUIRE(module != nullptr);

    CHECK(module->size() > 0);
    CHECK(module->imagebase() > 0);
    CHECK(module->name() == "librt.so.1");
    CHECK_THAT(module->path(), Catch::Matchers::EndsWith("librt.so.1"));
  }

  SECTION("dump") {
    void* H = dlopen("librt.so.1", RTLD_NOW);
    REQUIRE(H != nullptr);
    std::unique_ptr<Module> module = Module::from_handle(H);
    REQUIRE(module != nullptr);
    REQUIRE(module->size() > 0);

    std::vector<uint8_t> data = module->dump();
    CHECK(data.size() == module->size());
    REQUIRE(data.size() >= 4);
    CHECK(std::memcmp(data.data(), "\177ELF", 4) == 0);

    std::ostringstream os;
    std::vector<uint8_t> streamed = module->dump(os);
    CHECK(streamed.size() == module->size());
    const std::string buffer = os.str();
    REQUIRE(buffer.size() == streamed.size());
    CHECK(std::memcmp(buffer.data(), streamed.data(), streamed.size()) == 0);
  }

  SECTION("host") {
    CHECK(Host::sys_name() == "Linux");
    CHECK_FALSE(Host::sys_release().empty());
    CHECK_FALSE(Host::sys_version().empty());
    CHECK_FALSE(Host::hardware().empty());
  }
}
