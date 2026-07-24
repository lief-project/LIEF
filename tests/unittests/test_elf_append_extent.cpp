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
#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"

#include "utils.hpp"

using namespace LIEF;

namespace {

uint64_t recompute_extent(const ELF::Binary& binary) {
  uint64_t maximum = 0;

  for (const ELF::Section& section : binary.sections()) {
    if (section.is_frame() || section.type() == ELF::Section::TYPE::NOBITS) {
      continue;
    }

    maximum = std::max(maximum, section.file_offset() + section.size());
  }

  for (const ELF::Segment& segment : binary.segments()) {
    maximum = std::max(maximum,
                       segment.file_offset() + segment.physical_size());
  }

  return maximum;
}

uint64_t align_up(uint64_t value, uint64_t align) {
  if (align == 0) {
    return value;
  }

  const uint64_t remainder = value % align;
  if (remainder == 0) {
    return value;
  }

  return value + align - remainder;
}

ELF::Segment make_probe_segment(const ELF::Binary& binary) {
  ELF::Segment probe;
  probe.type(ELF::Segment::TYPE::LOAD);
  probe.alignment(binary.page_size());
  probe.content(std::vector<uint8_t>{0xCC});
  return probe;
}

ELF::Segment* append_and_check(ELF::Binary& binary) {
  REQUIRE((binary.header().file_type() == ELF::Header::FILE_TYPE::EXEC));

  const uint64_t expected_offset = align_up(
    recompute_extent(binary),
    binary.page_size()
  );

  ELF::Segment probe = make_probe_segment(binary);
  ELF::Segment* added = binary.add(probe);

  REQUIRE(added != nullptr);
  CHECK(added->file_offset() == expected_offset);
  return added;
}

std::unique_ptr<ELF::Binary> parse_exec() {
  const std::string path = test::get_elf_sample(
    "ELF64_x86-64_binary_static-binary.bin"
  );

  std::unique_ptr<ELF::Binary> binary = ELF::Parser::parse(path);
  REQUIRE(binary != nullptr);
  REQUIRE((binary->header().file_type() == ELF::Header::FILE_TYPE::EXEC));
  return binary;
}

std::unique_ptr<ELF::Binary> make_segment_gap_exec() {
  std::unique_ptr<ELF::Binary> binary = parse_exec();

  const uint64_t phdr_size = binary->header().program_header_size();
  REQUIRE(phdr_size != 0);

  const auto current_phdrs =
    static_cast<uint64_t>(binary->header().numberof_segments());

  // relocate_phdr_table_v1() subtracts the current PHDR count from the
  // number of entries that fit in the gap, then requires the remainder to
  // be at least the current PHDR count. Add one entry as margin.
  const uint64_t required_entries = 2 * current_phdrs + 1;
  const uint64_t required_gap = required_entries * phdr_size;

  std::vector<ELF::Segment*> loads;
  for (ELF::Segment& segment : binary->segments()) {
    if (segment.is_load()) {
      loads.push_back(&segment);
    }
  }

  REQUIRE(loads.size() >= 2);

  ELF::Segment* current = nullptr;
  ELF::Segment* adjacent = nullptr;

  for (size_t i = 0; i + 1 < loads.size(); ++i) {
    ELF::Segment* candidate = loads[i];
    ELF::Segment* next = loads[i + 1];

    if (candidate->virtual_size() != candidate->physical_size()) {
      continue;
    }

    // Create the gap
    if (next->file_offset() <= candidate->file_offset() + required_gap) {
      continue;
    }

    current = candidate;
    adjacent = next;
    break;
  }

  REQUIRE(current != nullptr);
  REQUIRE(adjacent != nullptr);

  const uint64_t new_size = adjacent->file_offset() -
                            current->file_offset() -
                            required_gap;

  REQUIRE(new_size > 0);

  current->physical_size(new_size);
  current->virtual_size(new_size);

  const uint64_t actual_gap =
    adjacent->file_offset() -
    (current->file_offset() + current->physical_size());

  const uint64_t available_entries = actual_gap / phdr_size;

  REQUIRE(available_entries >= required_entries);
  REQUIRE(available_entries - current_phdrs >= current_phdrs);

  return binary;
}

std::unique_ptr<ELF::Binary> make_relocated_exec() {
  std::unique_ptr<ELF::Binary> binary = parse_exec();

  REQUIRE(binary->reserve_segments(256));
  REQUIRE(binary->relocate_phdr_table(
            ELF::Binary::PHDR_RELOC::BINARY_END) != 0);

  // Establish a valid cache and a known final maximum contributor
  append_and_check(*binary);
  return binary;
}

bool is_mutable_file_backed_section(const ELF::Section& section) {
  return !section.is_frame() &&
         section.type() != ELF::Section::TYPE::SHT_NULL_ &&
         section.type() != ELF::Section::TYPE::NOBITS &&
         section.size() != 0;
}

ELF::Section* first_file_backed_section(ELF::Binary& binary) {
  for (ELF::Section& section : binary.sections()) {
    if (is_mutable_file_backed_section(section)) {
      return &section;
    }
  }
  return nullptr;
}

ELF::Section* second_file_backed_section(ELF::Binary& binary) {
  bool found_first = false;

  for (ELF::Section& section : binary.sections()) {
    if (!is_mutable_file_backed_section(section)) {
      continue;
    }

    if (!found_first) {
      found_first = true;
      continue;
    }

    return &section;
  }
  return nullptr;
}

ELF::Segment* first_segment(ELF::Binary& binary) {
  for (ELF::Segment& segment : binary.segments()) {
    return &segment;
  }
  return nullptr;
}

ELF::Segment* last_segment(ELF::Binary& binary) {
  ELF::Segment* result = nullptr;

  for (ELF::Segment& segment : binary.segments()) {
    result = &segment;
  }
  return result;
}

void relocate_and_check(ELF::Binary& binary, ELF::Binary::PHDR_RELOC strategy) {
  const uint64_t result = binary.relocate_phdr_table(strategy);
  REQUIRE(result != 0);

  if (binary.header().file_type() != ELF::Header::FILE_TYPE::EXEC) {
    // add_segment<EXEC> is the cache consumer
    binary.header().file_type(ELF::Header::FILE_TYPE::EXEC);
  }

  append_and_check(binary);
}

} // namespace

TEST_CASE("ELF append extent: parse and repeated additions",
          "[lief][elf][append-extent]") {
  SECTION("first addition after parser publication") {
    std::unique_ptr<ELF::Binary> binary = parse_exec();

    REQUIRE(binary->reserve_segments(256));
    REQUIRE(binary->relocate_phdr_table(
              ELF::Binary::PHDR_RELOC::BINARY_END) != 0);

    append_and_check(*binary);
  }

  SECTION("repeated ET_EXEC additions") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();

    for (size_t i = 0; i < 128; ++i) {
      append_and_check(*binary);
    }
  }
}

TEST_CASE("ELF append extent: maximum contributors",
          "[lief][elf][append-extent]") {
  SECTION("section-only maximum") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    const uint64_t previous_end = recompute_extent(*binary);
    const uint64_t page = binary->page_size();

    section->size(0);
    section->offset(previous_end + page);
    section->size(page);

    append_and_check(*binary);
  }

  SECTION("segment-only maximum") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();

    // The probe inserted by make_relocated_exec() is the unique final segment
    append_and_check(*binary);
  }

  SECTION("equal section and segment maxima") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    ELF::Segment* segment = last_segment(*binary);

    REQUIRE(section != nullptr);
    REQUIRE(segment != nullptr);

    const uint64_t maximum = segment->file_offset() + segment->physical_size();

    section->size(0);
    section->offset(maximum);
    section->size(0);

    append_and_check(*binary);
  }
}

TEST_CASE("ELF append extent: incremental size and offset changes",
          "[lief][elf][append-extent]") {
  SECTION("grow a nonmaximum section") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    const uint64_t maximum = recompute_extent(*binary);

    section->offset(0);
    section->size(std::min<uint64_t>(maximum / 2, 0x2000));
    section->size(section->size() + 1);

    REQUIRE(section->file_offset() + section->size() < maximum);
    append_and_check(*binary);
  }

  SECTION("shrink a nonmaximum section") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    const uint64_t maximum = recompute_extent(*binary);

    section->offset(0);
    section->size(std::min<uint64_t>(maximum / 2, 0x2000));
    REQUIRE(section->size() > 0);
    section->size(section->size() - 1);

    REQUIRE(section->file_offset() + section->size() < maximum);
    append_and_check(*binary);
  }

  SECTION("grow the maximum") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Segment* maximum = last_segment(*binary);
    REQUIRE(maximum != nullptr);

    maximum->physical_size(maximum->physical_size() + binary->page_size());

    append_and_check(*binary);
  }

  SECTION("shrink one of multiple maximum contributors") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    ELF::Segment* segment = last_segment(*binary);

    REQUIRE(section != nullptr);
    REQUIRE(segment != nullptr);

    const uint64_t maximum = segment->file_offset() + segment->physical_size();

    section->size(0);
    section->offset(maximum);
    section->size(0);

    section->offset(0);

    // ...the segment remains at maximum...

    append_and_check(*binary);
  }

  SECTION("shrink the last maximum contributor") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Segment* maximum = last_segment(*binary);
    REQUIRE(maximum != nullptr);

    maximum->physical_size(0);
    maximum->file_offset(0);

    append_and_check(*binary);
  }
}

TEST_CASE("ELF append extent: section contribution transitions",
          "[lief][elf][append-extent]") {
  SECTION("PROGBITS to NOBITS") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    const uint64_t previous_end = recompute_extent(*binary);
    const uint64_t page = binary->page_size();

    section->size(0);
    section->offset(previous_end + page);
    section->size(page);

    REQUIRE(recompute_extent(*binary) == previous_end + 2 * page);

    section->type(ELF::Section::TYPE::NOBITS);
    append_and_check(*binary);
  }

  SECTION("NOBITS to PROGBITS") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    const uint64_t previous_end = recompute_extent(*binary);
    const uint64_t page = binary->page_size();

    section->type(ELF::Section::TYPE::NOBITS);
    section->size(page);
    section->offset(previous_end + page);
    section->type(ELF::Section::TYPE::PROGBITS);

    append_and_check(*binary);
  }

  SECTION("convert maximum section to frame") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    const uint64_t previous_end = recompute_extent(*binary);
    const uint64_t page = binary->page_size();

    section->size(0);
    section->offset(previous_end + page);
    section->size(page);
    section->as_frame();

    append_and_check(*binary);
  }

  SECTION("publish an already-framed section") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();

    ELF::Section frame{".append_extent_frame", ELF::Section::TYPE::PROGBITS};
    frame.offset(std::numeric_limits<uint64_t>::max() - 0x2000);
    frame.size(0x1000);
    frame.as_frame();

    ELF::Section* added = binary->add(frame, false);
    REQUIRE(added != nullptr);
    REQUIRE(added->is_frame());

    append_and_check(*binary);
  }
}

TEST_CASE("ELF append extent: removal and replacement",
          "[lief][elf][append-extent]") {
  SECTION("remove section") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* section = first_file_backed_section(*binary);
    REQUIRE(section != nullptr);

    binary->remove(*section, false);
    append_and_check(*binary);
  }

  SECTION("remove maximum segment") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Segment* segment = last_segment(*binary);
    REQUIRE(segment != nullptr);

    binary->remove(*segment, false);
    append_and_check(*binary);
  }

  SECTION("replace segment") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Segment* original = last_segment(*binary);
    REQUIRE(original != nullptr);

    ELF::Segment replacement{*original};
    replacement.file_offset(recompute_extent(*binary) + binary->page_size());
    replacement.content(std::vector<uint8_t>(0x80, 0x5a));
    replacement.physical_size(0x80);
    replacement.virtual_size(0x80);

    ELF::Segment* inserted = binary->replace(replacement, *original);
    REQUIRE(inserted != nullptr);

    append_and_check(*binary);
  }
}

TEST_CASE("ELF append extent: attached-object assignment",
          "[lief][elf][append-extent]") {
  SECTION("section assignment") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* attached = first_file_backed_section(*binary);
    REQUIRE(attached != nullptr);

    ELF::Section replacement{".replacement", ELF::Section::TYPE::PROGBITS};
    replacement.offset(recompute_extent(*binary) + binary->page_size());
    replacement.size(binary->page_size());

    *attached = replacement;
    append_and_check(*binary);
  }

  SECTION("segment assignment") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Segment* attached = first_segment(*binary);
    REQUIRE(attached != nullptr);

    ELF::Segment replacement;
    replacement.type(ELF::Segment::TYPE::LOAD);
    replacement.file_offset(recompute_extent(*binary) + binary->page_size());
    replacement.physical_size(binary->page_size());
    replacement.virtual_size(binary->page_size());

    *attached = replacement;
    append_and_check(*binary);
  }
}

TEST_CASE("ELF append extent: attached and detached swaps",
          "[lief][elf][append-extent]") {
  SECTION("section swap") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Section* attached = first_file_backed_section(*binary);
    REQUIRE(attached != nullptr);

    ELF::Section detached{".detached", ELF::Section::TYPE::PROGBITS};
    detached.offset(recompute_extent(*binary) + binary->page_size());
    detached.size(binary->page_size());

    attached->swap(detached);
    append_and_check(*binary);
  }

  SECTION("segment swap") {
    std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
    ELF::Segment* attached = first_segment(*binary);
    REQUIRE(attached != nullptr);

    ELF::Segment detached;
    detached.type(ELF::Segment::TYPE::LOAD);
    detached.file_offset(recompute_extent(*binary) + binary->page_size());
    detached.physical_size(binary->page_size());
    detached.virtual_size(binary->page_size());

    attached->swap(detached);
    append_and_check(*binary);
  }
}

TEST_CASE("ELF append extent: cross-binary swaps",
          "[lief][elf][append-extent]") {
  SECTION("section swap across binaries") {
    std::unique_ptr<ELF::Binary> lhs = make_relocated_exec();
    std::unique_ptr<ELF::Binary> rhs = make_relocated_exec();

    ELF::Section* lhs_section = first_file_backed_section(*lhs);
    ELF::Section* rhs_section = second_file_backed_section(*rhs);

    REQUIRE(lhs_section != nullptr);
    REQUIRE(rhs_section != nullptr);

    lhs_section->swap(*rhs_section);

    append_and_check(*lhs);
    append_and_check(*rhs);
  }

  SECTION("segment swap across binaries") {
    std::unique_ptr<ELF::Binary> lhs = make_relocated_exec();
    std::unique_ptr<ELF::Binary> rhs = make_relocated_exec();

    ELF::Segment* lhs_segment = first_segment(*lhs);
    ELF::Segment* rhs_segment = last_segment(*rhs);

    REQUIRE(lhs_segment != nullptr);
    REQUIRE(rhs_segment != nullptr);

    lhs_segment->swap(*rhs_segment);

    append_and_check(*lhs);
    append_and_check(*rhs);
  }
}

TEST_CASE("ELF append extent: section and segment shifts",
          "[lief][elf][append-extent]") {
  std::unique_ptr<ELF::Binary> binary = make_relocated_exec();
  ELF::Segment* segment = first_segment(*binary);
  REQUIRE(segment != nullptr);

  REQUIRE(binary->extend(*segment, binary->page_size()));
  append_and_check(*binary);
}

TEST_CASE("ELF append extent: empty layout",
          "[lief][elf][append-extent]") {
  std::unique_ptr<ELF::Binary> binary = make_relocated_exec();

  std::vector<ELF::Section*> sections;
  for (ELF::Section& section : binary->sections()) {
    sections.push_back(&section);
  }

  for (ELF::Section* section : sections) {
    binary->remove(*section, false);
  }

  std::vector<ELF::Segment*> segments;
  for (ELF::Segment& segment : binary->segments()) {
    segments.push_back(&segment);
  }

  for (ELF::Segment* segment : segments) {
    binary->remove(*segment, false);
  }

  REQUIRE(recompute_extent(*binary) == 0);
  append_and_check(*binary);
}

TEST_CASE("ELF append extent: PHDR relocation layouts",
          "[lief][elf][append-extent]") {
  SECTION("BINARY_END") {
    std::unique_ptr<ELF::Binary> binary = parse_exec();
    REQUIRE(binary->reserve_segments(32));

    relocate_and_check(*binary, ELF::Binary::PHDR_RELOC::BINARY_END);
  }

  SECTION("SEGMENT_GAP") {
    std::unique_ptr<ELF::Binary> binary = make_segment_gap_exec();
    relocate_and_check(*binary, ELF::Binary::PHDR_RELOC::SEGMENT_GAP);
  }

  SECTION("BSS_END") {
    std::unique_ptr<ELF::Binary> binary = parse_exec();
    relocate_and_check(*binary, ELF::Binary::PHDR_RELOC::BSS_END);
  }
}

