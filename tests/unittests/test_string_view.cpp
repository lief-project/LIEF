/* Copyright 2026 R. Thomas
 * Copyright 2026 Quarkslab
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
#include <functional>
#include <string>
#include <vector>

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/utils.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/config.h"
#include "LIEF/hash.hpp"
#include "LIEF/iostream.hpp"
#include "LIEF/utils.hpp"

#include "utils.hpp"

using namespace LIEF;
using namespace std::string_view_literals;

TEST_CASE("String views respect their bounds", "[string-view]") {
  SECTION("Symbol lookup and removal accept borrowed names") {
    auto bin = ELF::Parser::parse(test::get_elf_sample("ELF32_ARM_binary_ls.bin"));
    REQUIRE(bin != nullptr);

    const std::string name(80, 'x');
    const std::string buffer = name + "suffix";
    const std::string_view view(buffer.data(), name.size());
    ELF::Symbol symbol(name);
    auto& added = bin->add_symtab_symbol(symbol);
    bin->add_dynamic_symbol(symbol);

    CHECK(bin->get_symtab_symbol(view) == &added);
    CHECK(bin->has_dynamic_symbol(view));
    CHECK(bin->has_symbol(view));
    CHECK(bin->get_symtab_symbol(buffer) == nullptr);
    CHECK(bin->dynsym_idx(name) == bin->dynsym_idx(view));
    CHECK(bin->symtab_idx(name) == bin->symtab_idx(view));
    CHECK(bin->get_relocation(name) == nullptr);

    const std::string_view owned_by_symbol = added.name();
    bin->remove_symbol(owned_by_symbol);
    CHECK_FALSE(bin->has_symtab_symbol(view));
    CHECK_FALSE(bin->has_dynamic_symbol(view));
  }

  SECTION("Setters and factories keep their own copy") {
    std::string buffer = "library.dllsuffix";
    const std::string_view name(buffer.data(), 11);
    PE::Binary bin;
    auto& imported = bin.add_import(name);
    CHECK(bin.get_import(name) == &imported);
    imported.add_entry(std::string("function"));
    CHECK(imported.get_entry("function") != nullptr);

    auto dylib = MachO::DylibCommand::load_dylib(name);
    ELF::DynamicEntryRunPath runpath;
    runpath += name;
    buffer.assign(buffer.size(), 'x');
    CHECK(imported.name() == "library.dll");
    CHECK(dylib.name() == "library.dll");
    CHECK(runpath.runpath() == "library.dll");
  }

  SECTION("Binary strings include embedded zero bytes") {
    const char buffer[] = {'a', '\0', char(0xff), 'x'};
    const std::string_view view(buffer, 3);
    const std::vector<uint8_t> expected = {'a', 0, 0xff};
    PE::ResourceData data(view);
    CHECK(std::vector<uint8_t>(data.content().begin(), data.content().end()) ==
          expected);

    ELF::Section section(".data");
    section.content({'a', 0, 0xff, 'a', 0, 0xff});
    CHECK(section.search(view) == 0);
    CHECK(section.search_all(view) == std::vector<size_t>{0, 3});

    vector_iostream stream;
    stream.write(view);
    CHECK(stream.raw() == std::vector<uint8_t>{'a', 0, 0xff, 0});
    stream.write(std::string_view{});
    CHECK(stream.raw().back() == 0);
    CHECK(stream.size() == 5);

    Hash hash(0x123);
    CHECK(hash.process(view).value() ==
          Hash::combine(size_t(0x123),
                        std::hash<std::string>{}(std::string(view))));
  }

  SECTION("Hash and note helpers do not read past the view") {
    const char name[] = {'G', 'N', 'U', 'x'};
    const std::string_view view(name, 3);
    CHECK(ELF::hash32(view) == ELF::hash32("GNU"));
    CHECK(ELF::hash64(view) == ELF::hash64("GNU"));
    CHECK(ELF::dl_new_hash(view) == ELF::dl_new_hash("GNU"));
    CHECK(ELF::hash32("GNU\0ignored"sv) == ELF::hash32(view));
    CHECK(ELF::hash64("GNU\0ignored"sv) == ELF::hash64(view));
    CHECK(ELF::dl_new_hash("GNU\0ignored"sv) == ELF::dl_new_hash(view));
    CHECK(ELF::hash32({}) == 0);
    CHECK(ELF::hash64({}) == 0);
    CHECK(ELF::dl_new_hash({}) == 5381);

    auto note = ELF::Note::create(view, ELF::Note::TYPE::GNU_BUILD_ID, {1, 2, 3},
                                  ".note.gnu.build-id");
    REQUIRE(note != nullptr);
    CHECK(note->name() == "GNU");
    CHECK(ELF::Note::convert_type(ELF::Header::FILE_TYPE::EXEC, 3, view).value() ==
          ELF::Note::TYPE::GNU_BUILD_ID);

    const std::string_view oid = "1.3.14.3.2.26suffix"sv.substr(0, 13);
    CHECK(PE::algo_from_oid(oid) == PE::ALGORITHMS::SHA_1);
  }

  SECTION("Text conversion accepts substrings and empty views") {
    const char text[] = {'a', '\0', 'b', 'x'};
    const auto converted = u8tou16(std::string_view(text, 3));
    REQUIRE(converted);
    CHECK(*converted == std::u16string({u'a', 0, u'b'}));
    CHECK(u8tou16({}).value().empty());
  }
}
