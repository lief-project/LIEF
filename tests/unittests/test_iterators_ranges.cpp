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
// LIEF comes first: the detection of the std::ranges support must not depend
// on the standard headers included before LIEF's ones
#include "LIEF/ELF.hpp"

#include <catch2/catch_test_macros.hpp>

#include <LIEF/iterators.hpp>

#include <string_view>
#include <algorithm>
#include <memory>
#include <ranges>
#include <string>
#include <vector>

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Symbol.hpp"

#include "utils.hpp"

using namespace LIEF;

using strings_t = std::vector<std::string>;
using unique_strings_t = std::vector<std::unique_ptr<std::string>>;

using it_ref = ref_iterator<strings_t&>;
using it_const_ref = const_ref_iterator<const strings_t&>;
using it_owning = ref_iterator<strings_t>;
using it_const_owning = const_ref_iterator<strings_t>;
using it_ptr = ref_iterator<unique_strings_t&, std::string*>;
using it_const_ptr =
    const_ref_iterator<const unique_strings_t&, const std::string*>;
using it_owning_ptr = ref_iterator<std::vector<std::string*>>;

using it_filter = filter_iterator<strings_t&>;
using it_const_filter = const_filter_iterator<const strings_t&>;
using it_filter_owning = filter_iterator<strings_t>;
using it_filter_ptr = filter_iterator<std::vector<std::string*>>;

template<class It>
constexpr bool is_bidirectional_range =
    std::bidirectional_iterator<It> && std::sized_sentinel_for<It, It> &&
    std::ranges::bidirectional_range<It> &&
    std::ranges::bidirectional_range<const It> && std::ranges::sized_range<It> &&
    std::ranges::common_range<It> && std::ranges::viewable_range<It> &&
    std::ranges::viewable_range<It&>;

template<class It>
constexpr bool is_forward_range =
    std::forward_iterator<It> && std::ranges::forward_range<It> &&
    std::ranges::forward_range<const It> && std::ranges::common_range<It> &&
    std::ranges::viewable_range<It> && std::ranges::viewable_range<It&>;

template<class It>
constexpr bool is_input_range =
    std::input_iterator<It> && !std::forward_iterator<It> &&
    std::ranges::input_range<It> && std::ranges::input_range<const It> &&
    std::ranges::sized_range<It> && std::ranges::viewable_range<It> &&
    std::ranges::viewable_range<It&>;

// Iterators that borrow their container: they are views and their iterators
// only reference elements that outlive the range
static_assert(is_bidirectional_range<it_ref>);
static_assert(is_bidirectional_range<it_const_ref>);
static_assert(is_bidirectional_range<it_ptr>);
static_assert(is_bidirectional_range<it_const_ptr>);
static_assert(is_forward_range<it_filter>);
static_assert(is_forward_range<it_const_filter>);

static_assert(std::ranges::view<it_ref> && std::ranges::borrowed_range<it_ref>);
static_assert(std::ranges::view<it_const_ref> &&
              std::ranges::borrowed_range<it_const_ref>);
static_assert(std::ranges::view<it_ptr> && std::ranges::borrowed_range<it_ptr>);
static_assert(std::ranges::view<it_filter> &&
              std::ranges::borrowed_range<it_filter>);

static_assert(is_bidirectional_range<ELF::Binary::it_segments>);
static_assert(is_bidirectional_range<ELF::Binary::it_const_segments>);
static_assert(is_forward_range<ELF::Binary::it_dynamic_relocations>);
static_assert(std::ranges::view<ELF::Binary::it_segments>);
static_assert(std::ranges::view<ELF::Binary::it_dynamic_relocations>);

// Iterators that own a container of pointers: they copy the container (they
// are not views) but they reference the pointed objects, which outlive the
// range
static_assert(is_bidirectional_range<it_owning_ptr>);
static_assert(is_forward_range<it_filter_ptr>);
static_assert(is_forward_range<ELF::Binary::it_exported_symbols>);
static_assert(!std::ranges::view<it_owning_ptr> &&
              std::ranges::borrowed_range<it_owning_ptr>);
static_assert(!std::ranges::view<it_filter_ptr> &&
              std::ranges::borrowed_range<it_filter_ptr>);

// Iterators that own a container of values: the references are bound to the
// copy of the container owned by the iterator so they are only input
// iterators
static_assert(is_input_range<it_owning>);
static_assert(is_input_range<it_const_owning>);
static_assert(is_input_range<it_filter_owning>);
static_assert(!std::ranges::view<it_owning> &&
              !std::ranges::borrowed_range<it_owning>);
static_assert(!std::ranges::view<it_filter_owning> &&
              !std::ranges::borrowed_range<it_filter_owning>);
static_assert(std::same_as<decltype(std::ranges::find(it_owning{}, "")),
                           std::ranges::dangling>);

static_assert(std::same_as<std::iter_value_t<it_ptr>, std::string>);
static_assert(std::same_as<std::iter_value_t<it_const_ptr>, std::string>);
static_assert(
    std::same_as<std::iter_reference_t<it_const_ptr>, const std::string&>
);

inline int to_int(const std::string& value) {
  return value.front() - '0';
}

inline bool is_even(const std::string& value) {
  return to_int(value) % 2 == 0;
}

inline strings_t to_vector(std::ranges::input_range auto&& range) {
  strings_t out;
  for (const std::string& value : range) {
    out.push_back(value);
  }
  return out;
}

TEST_CASE("lief.test.iterators.ranges.ref_iterator", "[lief][iterators][ranges]") {
  strings_t values = {"1", "2", "3", "4", "5", "6"};

  SECTION("views") {
    CHECK(to_vector(it_ref{values} | std::views::filter(is_even)) ==
          strings_t{"2", "4", "6"});

    CHECK(to_vector(it_ref{values} | std::views::reverse | std::views::take(2)) ==
          strings_t{"6", "5"});

    CHECK(to_vector(it_const_ref{values} | std::views::drop(4)) ==
          strings_t{"5", "6"});

    auto ints = it_ref{values} | std::views::transform(to_int);
    CHECK(std::ranges::equal(ints, std::vector<int>{1, 2, 3, 4, 5, 6}));

    it_ref range{values};
    auto filtered = range | std::views::filter(is_even);
    CHECK(to_vector(filtered) == strings_t{"2", "4", "6"});

    for (std::string& value : it_ref{values} | std::views::filter(is_even)) {
      value += '!';
    }
    CHECK(values == strings_t{"1", "2!", "3", "4!", "5", "6!"});
  }

  SECTION("algorithms") {
    auto it = std::ranges::find(it_ref{values}, "3");
    REQUIRE(it != it.end());
    CHECK(&*it == &values[2]);

    CHECK(std::ranges::count_if(it_const_ref{values}, is_even) == 3);
    CHECK(std::ranges::size(it_ref{values}) == values.size());
    CHECK(std::ranges::distance(it_ref{values}) == 6);
    CHECK(std::ranges::equal(it_const_ref{values}, values));
  }

  SECTION("pointers") {
    unique_strings_t pointers;
    pointers.push_back(std::make_unique<std::string>("1"));
    pointers.push_back(std::make_unique<std::string>("2"));

    auto it = std::ranges::find(it_const_ptr{pointers}, "2");
    REQUIRE(it != it.end());
    CHECK(&*it == pointers[1].get());

    CHECK(to_vector(it_ptr{pointers} | std::views::reverse) ==
          strings_t{"2", "1"});
  }

  SECTION("owning") {
    auto view = it_owning{values} | std::views::filter(is_even);
    values.clear();
    CHECK(to_vector(view) == strings_t{"2", "4", "6"});
    static_assert(!std::ranges::forward_range<decltype(view)>);

    strings_t storage = {"1", "2"};
    std::vector<std::string*> pointers = {&storage[0], &storage[1]};
    auto reversed = it_owning_ptr{pointers} | std::views::reverse;
    pointers.clear();
    CHECK(to_vector(reversed) == strings_t{"2", "1"});
    CHECK(&*reversed.begin() == &storage[1]);
  }
}

TEST_CASE("lief.test.iterators.ranges.filter_iterator",
          "[lief][iterators][ranges]") {
  strings_t values = {"1", "2", "3", "4", "5", "6"};

  it_filter even{values, is_even};
  CHECK(to_vector(even) == strings_t{"2", "4", "6"});

  CHECK(to_vector(even | std::views::take(2)) == strings_t{"2", "4"});

  auto ints = even | std::views::transform(to_int);
  CHECK(std::ranges::equal(ints, std::vector<int>{2, 4, 6}));

  auto it = std::ranges::find(it_filter{values, is_even}, "4");
  REQUIRE(it != it.end());
  CHECK(&*it == &values[3]);

  CHECK(std::ranges::distance(it_const_filter{values, is_even}) == 3);

  auto owning = it_filter_owning{values, is_even} | std::views::drop(1);
  values.clear();
  CHECK(to_vector(owning) == strings_t{"4", "6"});
}

TEST_CASE("lief.test.iterators.ranges.elf", "[lief][iterators][ranges]") {
  std::unique_ptr<ELF::Binary> elf =
      ELF::Parser::parse(test::get_elf_sample("ELF64_x86-64_binary_ls.bin"));
  REQUIRE(elf != nullptr);

  size_t nb_load = 0;
  for (const ELF::Segment& segment : elf->segments()) {
    if (segment.is_load()) {
      ++nb_load;
    }
  }
  REQUIRE(nb_load > 0);

  auto loads = elf->segments() | std::views::filter(&ELF::Segment::is_load);
  CHECK(size_t(std::ranges::distance(loads)) == nb_load);

  for (const ELF::Segment& segment : loads) {
    CHECK(segment.is_load());
  }

  const ELF::Binary& const_elf = *elf;
  CHECK(std::ranges::count_if(const_elf.segments(), &ELF::Segment::is_load) ==
        std::ptrdiff_t(nb_load));

  auto first_load = std::ranges::find_if(elf->segments(), &ELF::Segment::is_load);
  REQUIRE(first_load != first_load.end());
  CHECK(&*first_load == &*loads.begin());

  ELF::Binary::it_exported_symbols exported = elf->exported_symbols();
  REQUIRE(!exported.empty());
  auto names = exported | std::views::transform([](const ELF::Symbol& sym) {
                 return sym.name();
               });
  CHECK(size_t(std::ranges::distance(names.begin(), names.end())) ==
        exported.size());
  CHECK(std::ranges::none_of(names,
                             [](std::string_view name) { return name.empty(); }));

  ELF::Binary::it_dynamic_relocations relocations = elf->dynamic_relocations();
  CHECK(size_t(std::ranges::distance(relocations.begin(), relocations.end())) ==
        relocations.size());
}
