/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include <numeric>

#include "easylogging++.h"

#include "LIEF/BinaryStream/VectorStream.hpp"

namespace LIEF {
namespace ELF {

template<class ELF_T>
void Builder::build(void) {

  std::string type = ((this->binary_->type_ == ELFCLASS32) ? "ELF32" : "ELF64");
  LOG(DEBUG) << "== Re-building " << type << " ==";
  try {
    this->build_hash_table<ELF_T>();
  } catch (const LIEF::exception& e) {
    LOG(ERROR) << e.what();
  }

  try {
    this->build_dynamic<ELF_T>();
  } catch (const LIEF::exception& e) {
    LOG(ERROR) << e.what();
  }

  if (this->binary_->symbol_version_table_.size() > 0) {
    try {
      this->build_symbol_version();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->symbol_version_requirements_.size() > 0) {
    try {
      this->build_symbol_requirement<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->symbol_version_definition_.size() > 0) {
    try {
      this->build_symbol_definition<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->static_symbols_.size() > 0) {
    try {
      this->build_static_symbols<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->get_dynamic_relocations().size() > 0) {
    try {
      this->build_dynamic_relocations<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->get_pltgot_relocations().size() > 0) {
    try {
      this->build_pltgot_relocations<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->get_header().program_headers_offset() > 0) {
    this->build_segments<ELF_T>();
  } else {
    LOG(WARNING) << "Segments offset is null";
  }

  this->build_sections<ELF_T>();

  this->build_header<ELF_T>();

}


template<typename T, typename HANDLER>
std::vector<std::string> Builder::optimize(const HANDLER& e) {

  auto setPropertie = [] (const std::string& a, const std::string& b) {
    return (a.size() >= b.size() and a != b);
  };

  // Container which will hold the section name sorted by length
  std::set<std::string, decltype(setPropertie)> stringTable{setPropertie};

  std::vector<std::string> stringTableOpti;

  std::transform(
    std::begin(e),
    std::end(e),
    std::inserter(
      stringTable,
      std::end(stringTable)),
    std::mem_fn(static_cast<const std::string& (T::*)(void) const>(&T::name)));

  // Optimize the string table
  std::copy_if(
  std::begin(stringTable),
  std::end(stringTable),
  std::back_inserter(stringTableOpti),
  [&stringTableOpti] (const std::string& name)
  {
    auto it = std::find_if(
        std::begin(stringTableOpti),
        std::end(stringTableOpti),
        [&name] (const std::string& nameOpti) {
          return nameOpti.substr(nameOpti.size() - name.size()) == name ;
        });

    return (it == std::end(stringTableOpti));

  });

  return stringTableOpti;
}


template<typename ELF_T>
void Builder::build_header(void) {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Ehdr = typename ELF_T::Elf_Ehdr;

  const Header& header = this->binary_->get_header();
  Elf_Ehdr ehdr;

  ehdr.e_type      = static_cast<Elf_Half>(header.file_type());
  ehdr.e_machine   = static_cast<Elf_Half>(header.machine_type());
  ehdr.e_version   = static_cast<Elf_Word>(header.object_file_version());
  ehdr.e_entry     = static_cast<Elf_Addr>(header.entrypoint());
  ehdr.e_phoff     = static_cast<Elf_Off>(header.program_headers_offset());
  ehdr.e_shoff     = static_cast<Elf_Off>(header.section_headers_offset());
  ehdr.e_flags     = static_cast<Elf_Word>(header.processor_flag());
  ehdr.e_ehsize    = static_cast<Elf_Half>(header.header_size());
  ehdr.e_phentsize = static_cast<Elf_Half>(header.program_header_size());
  ehdr.e_phnum     = static_cast<Elf_Half>(header.numberof_segments());
  ehdr.e_shentsize = static_cast<Elf_Half>(header.section_header_size());
  ehdr.e_shnum     = static_cast<Elf_Half>(header.numberof_sections());
  ehdr.e_shstrndx  = static_cast<Elf_Half>(header.section_name_table_idx());

  std::copy(
    std::begin(header.identity()),
    std::end(header.identity()),
    std::begin(ehdr.e_ident));

  this->ios_.seekp(0);
  this->ios_.write(reinterpret_cast<const uint8_t*>(&ehdr), sizeof(Elf_Ehdr));
}


template<typename ELF_T>
void Builder::build_sections(void) {
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Shdr = typename ELF_T::Elf_Shdr;
  LOG(DEBUG) << "[+] Build sections";

  const Header& header = this->binary_->get_header();
  const uint64_t section_headers_offset = header.section_headers_offset();

  /////////////////////////
  ////////////////////////
  ///////////////////////
  std::vector<std::string> stringTableOpti =
    this->optimize<Section, decltype(this->binary_->sections_)>(this->binary_->sections_);

  // Build section's name
  std::vector<uint8_t> section_names;
  for (const std::string& name : stringTableOpti) {
    section_names.insert(std::end(section_names), std::begin(name), std::end(name));
    section_names.push_back(0);
  }

  Section* string_names_section = this->binary_->sections_[header.section_name_table_idx()];
  string_names_section->content(section_names);

  for (size_t i = 0; i < this->binary_->sections_.size(); i++) {
    const Section* section = this->binary_->sections_[i];

    auto&& it_offset_name = std::search(
        std::begin(section_names),
        std::end(section_names),
        section->name().c_str(),
        section->name().c_str() + section->name().size() + 1);

    if (it_offset_name == std::end(section_names)) {
      throw LIEF::not_found(""); // TODO: msg
    }

    const uint64_t offset_name = static_cast<uint64_t>(std::distance(std::begin(section_names), it_offset_name));

    Elf_Shdr shdr;
    shdr.sh_name      = static_cast<Elf_Word>(offset_name);
    shdr.sh_type      = static_cast<Elf_Word>(section->type());
    shdr.sh_flags     = static_cast<Elf_Word>(section->flags());
    shdr.sh_addr      = static_cast<Elf_Addr>(section->virtual_address());
    shdr.sh_offset    = static_cast<Elf_Off>(section->file_offset());
    shdr.sh_size      = static_cast<Elf_Word>(section->size());
    shdr.sh_link      = static_cast<Elf_Word>(section->link());
    shdr.sh_info      = static_cast<Elf_Word>(section->information());
    shdr.sh_addralign = static_cast<Elf_Word>(section->alignment());
    shdr.sh_entsize   = static_cast<Elf_Word>(section->entry_size());

    // Write Section'header
    if (section_headers_offset > 0) {
      this->ios_.seekp(section_headers_offset + i * sizeof(Elf_Shdr));
      this->ios_.write(reinterpret_cast<const uint8_t*>(&shdr), sizeof(Elf_Shdr));
    }

    // Write Section's content
    if (section->type() != SECTION_TYPES::SHT_NOBITS) {
        const std::vector<uint8_t>& content = section->content();
        // TODO: Assert sh_size == content.size()
        this->ios_.seekp(shdr.sh_offset);
        this->ios_.write(content.data(), shdr.sh_size);
    }
  }
}


template<typename ELF_T>
void Builder::build_segments(void) {
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Phdr = typename ELF_T::Elf_Phdr;
  LOG(DEBUG) << "[+] Build segments";

  std::vector<uint8_t> pheaders;
  pheaders.reserve(this->binary_->segments_.size() * sizeof(Elf_Phdr));

  for (const Segment* segment : this->binary_->segments_) {
      Elf_Phdr phdr;
      phdr.p_type   = static_cast<Elf_Word>(segment->type());
      phdr.p_flags  = static_cast<Elf_Word>(segment->flag());
      phdr.p_offset = static_cast<Elf_Off>(segment->file_offset());
      phdr.p_vaddr  = static_cast<Elf_Addr>(segment->virtual_address());
      phdr.p_paddr  = static_cast<Elf_Addr>(segment->physical_address());
      phdr.p_filesz = static_cast<Elf_Word>(segment->physical_size());
      phdr.p_memsz  = static_cast<Elf_Word>(segment->virtual_size());
      phdr.p_align  = static_cast<Elf_Word>(segment->alignment());

      pheaders.insert(
          std::end(pheaders),
          reinterpret_cast<uint8_t*>(&phdr),
          reinterpret_cast<uint8_t*>(&phdr) + sizeof(Elf_Phdr));
  }

  auto&& it_segment_phdr = std::find_if(
      std::begin(this->binary_->segments_),
      std::end(this->binary_->segments_),
      [] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_PHDR;
      });

  if (it_segment_phdr != std::end(this->binary_->segments_)) {
    (*it_segment_phdr)->content(pheaders);
  } else {
    const uint64_t segment_header_offset = this->binary_->get_header().program_headers_offset();
    this->ios_.seekp(segment_header_offset);
    this->ios_.write(pheaders);
  }

  // Write segment content
  for (const Segment* segment : this->binary_->segments_) {
    // If there isn't sections in the segments
    // We have to insert data in the segments because
    // we didn't do in `build_section()`
    if (segment->sections().size() == 0 and segment->physical_size() > 0) {
      const std::vector<uint8_t>& content = segment->content();
      LOG(DEBUG) << "Write content for segment " << *segment;
      LOG(DEBUG) << "Offset: 0x" << std::hex << segment->file_offset();
      LOG(DEBUG) << "Size: 0x" << std::hex << content.size();

      LOG(DEBUG) << "Content: " << std::accumulate(
        std::begin(content),
        std::begin(content) + 10,
        std::string(""),
        [] (std::string lhs, uint8_t x) {
          std::stringstream ss;
          ss << std::hex << static_cast<uint32_t>(x);
          return lhs.empty() ? ss.str() : lhs + " " + ss.str();
        });


      //TODO assert content.size == segmenthdr.physicalsize
      this->ios_.seekp(segment->file_offset());
      this->ios_.write(content);
    }
  }
}


template<typename ELF_T>
void Builder::build_static_symbols(void) {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Sym  = typename ELF_T::Elf_Sym;
  LOG(DEBUG) << "Build static symbols";

  Section& symbol_section = this->binary_->get_static_symbols_section();
  LOG(DEBUG) << "Section: " << symbol_section << std::endl;

  //clear
  //symbol_section.content(std::vector<uint8_t>(symbol_section.content().size(), 0));

  if (symbol_section.link() == 0 or
      symbol_section.link() >= this->binary_->sections_.size()) {
    throw LIEF::not_found("Unable to find a string section associated \
        with the Symbol section (sh_link)");
  }
  Section& symbol_str_section = *(this->binary_->sections_[symbol_section.link()]);

  std::vector<uint8_t> content;
  content.reserve(this->binary_->static_symbols_.size() * sizeof(Elf_Sym));
  std::vector<uint8_t> string_table;

  // Container which will hold symbols name (optimized)
  std::vector<std::string> string_table_optimize =
    this->optimize<Symbol, decltype(this->binary_->static_symbols_)>(this->binary_->static_symbols_);

  // We can't start with a symbol name
  string_table.push_back(0);
  for (const std::string& name : string_table_optimize) {
    string_table.insert(std::end(string_table), std::begin(name), std::end(name));
    string_table.push_back(0);
  }

  // Fill `content`
  for (const Symbol* symbol : this->binary_->static_symbols_) {
    LOG(DEBUG) << "Dealing with symbol: " << symbol->name();
    //TODO
    const std::string& name = symbol->name();

    // Check if name is already pressent
    auto&& it_name = std::search(
        std::begin(string_table),
        std::end(string_table),
        name.c_str(),
        name.c_str() + name.size() + 1);


    if (it_name == std::end(string_table)) {
      throw LIEF::not_found("Unable to find symbol '" + name + "' in the string table");
    }

    const uint64_t name_offset = static_cast<uint64_t>(std::distance(std::begin(string_table), it_name));

    Elf_Sym sym_hdr;
    sym_hdr.st_name  = static_cast<Elf_Word>(name_offset);
    sym_hdr.st_info  = static_cast<unsigned char>(symbol->information());
    sym_hdr.st_other = static_cast<unsigned char>(symbol->other());
    sym_hdr.st_shndx = static_cast<Elf_Half>(symbol->shndx());
    sym_hdr.st_value = static_cast<Elf_Addr>(symbol->value());
    sym_hdr.st_size  = static_cast<Elf_Word>(symbol->size());

    content.insert(
        std::end(content),
        reinterpret_cast<uint8_t*>(&sym_hdr),
        reinterpret_cast<uint8_t*>(&sym_hdr) + sizeof(Elf_Sym));
  }

  symbol_str_section.content(string_table);
  symbol_section.content(content);

}

/*!
 * \brief This method construct binary's dynamic part.
 *
 * Which include:
 *
 *   - Dynamic section
 *   - Dynamic string table
 *   - Dynamic symbol
 *   - Dynamic relocation
 */
template<typename ELF_T>
void Builder::build_dynamic(void) {
  LOG(DEBUG) << "Building dynamic part";

  if (this->binary_->dynamic_entries_.size() > 0) {
    this->build_dynamic_section<ELF_T>();
  }

  if (this->binary_->dynamic_symbols_.size() > 0) {
    this->build_dynamic_symbols<ELF_T>();
  }

}

template<typename ELF_T>
void Builder::build_dynamic_section(void) {
  using uint__     = typename ELF_T::uint;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;
  using Elf_Xword  = typename ELF_T::Elf_Xword;

  using Elf_Dyn    = typename ELF_T::Elf_Dyn;



  LOG(DEBUG) << "[+] Building dynamic section";

  const uint64_t dyn_strtab_va = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_STRTAB).value();

  Section& dyn_strtab_section = this->binary_->section_from_virtual_address(dyn_strtab_va);

  std::vector<uint8_t> dynamic_strings_raw;
  std::vector<uint8_t> dynamic_table_raw;

  for (DynamicEntry* entry : this->binary_->dynamic_entries_) {
    if (dynamic_cast<DynamicEntryLibrary*>(entry) or
        dynamic_cast<DynamicSharedObject*>(entry)) { // Contains library name
      const std::string& library_name = entry->name();
      dynamic_strings_raw.insert(
          std::end(dynamic_strings_raw),
          std::begin(library_name),
          std::end(library_name));
      dynamic_strings_raw.push_back(0);
      entry->value(dynamic_strings_raw.size() - library_name.size() - 1);
    }

    if (dynamic_cast<DynamicEntryRunPath*>(entry) or
        dynamic_cast<DynamicEntryRpath*>(entry)) { // contains path
      const std::string& path = entry->name();
      dynamic_strings_raw.insert(
          std::end(dynamic_strings_raw),
          std::begin(path),
          std::end(path));
      dynamic_strings_raw.push_back(0);
      entry->value(dynamic_strings_raw.size() - path.size() - 1);
    }

    //TODO: Update size
    if (dynamic_cast<DynamicEntryArray*>(entry)) { // contains array
      uint64_t address = entry->value();
      Segment& segment = this->binary_->segment_from_virtual_address(address);

      uint64_t rva                 = address - segment.virtual_address();
      std::vector<uint8_t> content = segment.content();
      std::vector<uint64_t>& array = entry->array();

      uint__* raw_array = reinterpret_cast<uint__*>(content.data() + rva);
      for(size_t i = 0; i < array.size(); ++i) {
        raw_array[i] = static_cast<uint__>(array[i]);
      }
      segment.content(content);
    }

    Elf_Dyn dynhdr;
    dynhdr.d_tag       = static_cast<Elf_Sxword>(entry->tag());
    dynhdr.d_un.d_val  = static_cast<Elf_Xword>(entry->value());

    dynamic_table_raw.insert(
      std::end(dynamic_table_raw),
      reinterpret_cast<uint8_t*>(&dynhdr),
      reinterpret_cast<uint8_t*>(&dynhdr) + sizeof(Elf_Dyn));
  }

  dyn_strtab_section.content(dynamic_strings_raw);
  this->binary_->get_dynamic_section().content(dynamic_table_raw);
}


template<typename ELF_T>
void Builder::build_symbol_hash(void) {
  LOG(DEBUG) << "Build SYSV Hash ";
  auto&& it_hash_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == SECTION_TYPES::SHT_HASH;
      });

  if (it_hash_section == std::end(this->binary_->sections_)) {
    return;
  }

  std::vector<uint8_t> content = (*it_hash_section)->content();
  VectorStream hashtable_stream{content};

  uint32_t nbucket = hashtable_stream.read_integer<uint32_t>(0);
  uint32_t nchain  = hashtable_stream.read_integer<uint32_t>(0 + sizeof(uint32_t));


  std::vector<uint8_t> new_hash_table((nbucket + nchain + 2) * sizeof(uint32_t), STN_UNDEF);
  uint32_t *new_hash_table_ptr = reinterpret_cast<uint32_t*>(new_hash_table.data());

  new_hash_table_ptr[0] = nbucket;
  new_hash_table_ptr[1] = nchain;

  uint32_t* bucket = &new_hash_table_ptr[2];
  uint32_t* chain  = &new_hash_table_ptr[2 + nbucket];
  uint32_t idx = 0;
  for (const Symbol* symbol : this->binary_->dynamic_symbols_) {
    uint32_t hash = 0;

    if (this->binary_->type_ == ELFCLASS32) {
      hash = hash32(symbol->name().c_str());
    } else {
      hash = hash64(symbol->name().c_str());
    }

    if(bucket[hash % nbucket] ==  STN_UNDEF) {
      bucket[hash % nbucket] = idx;
    } else {
      uint32_t value = bucket[hash % nbucket];
      while (chain[value] != STN_UNDEF) {
        value = chain[value];
        if (value >= (new_hash_table.size() / sizeof(uint32_t))) {
          LOG(ERROR) << "Out-of-bound for symbol" << symbol->name() << std::endl
                     << "Abort !";
          return;
        }
      }
      chain[value] = idx;
    }
    ++idx;

  }

  (*it_hash_section)->content(new_hash_table);
}

// Mainly inspired from
// * https://github.com/llvm-mirror/lld/blob/master/ELF/SyntheticSections.cpp
//
// Checking is performed here:
// * https://github.com/lattera/glibc/blob/a2f34833b1042d5d8eeb263b4cf4caaea138c4ad/elf/dl-lookup.c#L228
//
// See also:
// * p.9, https://www.akkadia.org/drepper/dsohowto.pdf
template<typename ELF_T>
void Builder::build_symbol_gnuhash(void) {
  using uint__ = typename ELF_T::uint;

  LOG(DEBUG) << "Rebuild GNU Hash table";

  const GnuHash& gnu_hash   = this->binary_->get_gnu_hash();

  const uint32_t nb_buckets = gnu_hash.nb_buckets();
  const uint32_t symndx     = gnu_hash.symbol_index();
  const uint32_t maskwords  = gnu_hash.maskwords();
  const uint32_t shift2     = gnu_hash.shift2();

  LOG(DEBUG) << "Number of buckets " << std::dec << nb_buckets;
  LOG(DEBUG) << "First symbol idx  " << std::dec << symndx;
  LOG(DEBUG) << "Number of bloom filters  " << std::dec << maskwords;
  LOG(DEBUG) << "Shift  " << std::dec << shift2;

  // MANDATORY !
  std::stable_sort(
      std::begin(this->binary_->dynamic_symbols_) + symndx,
      std::end(this->binary_->dynamic_symbols_),
      [&nb_buckets] (const Symbol* lhs, const Symbol* rhs) {
        return
          (dl_new_hash(lhs->name().c_str()) % nb_buckets) <
          (dl_new_hash(rhs->name().c_str()) % nb_buckets);
    });

  it_symbols dynamic_symbols = this->binary_->get_dynamic_symbols();

  std::vector<uint8_t> raw_gnuhash;
  raw_gnuhash.reserve(
      4 * sizeof(uint32_t) +          // header
      maskwords * sizeof(uint__) +    // bloom filters
      nb_buckets * sizeof(uint32_t) + // buckets
      (dynamic_symbols.size() - symndx) * sizeof(uint32_t)); // hash values


  // Write "header"
  // ==============

  // nb_buckets
  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<const uint8_t*>(&nb_buckets),
    reinterpret_cast<const uint8_t*>(&nb_buckets) + sizeof(uint32_t));

  // symndx
  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<const uint8_t*>(&symndx),
    reinterpret_cast<const uint8_t*>(&symndx) + sizeof(uint32_t));

  // maskwords
  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<const uint8_t*>(&maskwords),
    reinterpret_cast<const uint8_t*>(&maskwords) + sizeof(uint32_t));

  // shift2
  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<const uint8_t*>(&shift2),
    reinterpret_cast<const uint8_t*>(&shift2) + sizeof(uint32_t));



  // Compute Bloom filters
  // =====================
  std::vector<uint__> bloom_filters(maskwords, 0);
  size_t C = sizeof(uint__) * 8; // 32 for ELF, 64 for ELF64

  for (size_t i = symndx; i < dynamic_symbols.size(); ++i) {
    const uint32_t hash = dl_new_hash(dynamic_symbols[i].name().c_str());
    const size_t pos = (hash / C) & (gnu_hash.maskwords() - 1);
    uint__ V = (static_cast<uint__>(1) << (hash % C)) |
               (static_cast<uint__>(1) << ((hash >> gnu_hash.shift2()) % C));
    bloom_filters[pos] |= V;
  }
  for (size_t idx = 0; idx < bloom_filters.size(); ++idx) {
    LOG(DEBUG) << "Bloom filter [" << std::dec << idx << "]: " << std::hex << bloom_filters[idx];
  }

  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<uint8_t*>(bloom_filters.data()),
    reinterpret_cast<uint8_t*>(bloom_filters.data() + bloom_filters.size()));


  // Write buckets and hash
  // ======================
  int previous_bucket = -1;
  size_t hash_value_idx = 0;
  std::vector<uint32_t> buckets(nb_buckets, 0);
  std::vector<uint32_t> hash_values(dynamic_symbols.size() - symndx, 0);

  for (size_t i = symndx; i < dynamic_symbols.size(); ++i) {
    LOG(DEBUG) << "Dealing with symbol " << dynamic_symbols[i];
    const uint32_t hash = dl_new_hash(dynamic_symbols[i].name().c_str());
    int bucket = hash % nb_buckets;

    if (bucket < previous_bucket) {
      throw corrupted("Previous bucket is greater than the current one ("
          + std::to_string(bucket) + " < " +  std::to_string(previous_bucket) + ")");
    }

    if (bucket != previous_bucket) {
      buckets[bucket] = i;
      previous_bucket = bucket;
      if (hash_value_idx > 0) {
        hash_values[hash_value_idx - 1] |= 1;
      }
    }

    hash_values[hash_value_idx] = hash & ~1;
    ++hash_value_idx;
  }

  if (hash_value_idx > 0) {
    hash_values[hash_value_idx - 1] |= 1;
  }

  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<uint8_t*>(buckets.data()),
    reinterpret_cast<uint8_t*>(buckets.data() + buckets.size()));

  raw_gnuhash.insert(std::end(raw_gnuhash),
    reinterpret_cast<uint8_t*>(hash_values.data()),
    reinterpret_cast<uint8_t*>(hash_values.data() + hash_values.size()));

  auto&& it_gnuhash = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == SECTION_TYPES::SHT_GNU_HASH;
      });

  if (it_gnuhash == std::end(this->binary_->sections_)) {
    throw corrupted("Unable to find the .gnu.hash section");
  }

  if (raw_gnuhash.size()  <= (*it_gnuhash)->size()) {
    return (*it_gnuhash)->content(raw_gnuhash);
  } else { // Write a "null hash table"
    this->build_empty_symbol_gnuhash();
  }


}

template<typename ELF_T>
void Builder::build_hash_table(void) {
  LOG(DEBUG) << "Build hash table";
  auto&& it_hash = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == SECTION_TYPES::SHT_HASH;
      });


  auto&& it_gnuhash = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == SECTION_TYPES::SHT_GNU_HASH;
      });

  //TODO: To improve
  if (it_hash != std::end(this->binary_->sections_)) {
    this->build_symbol_hash<ELF_T>();
  }

  if (it_gnuhash != std::end(this->binary_->sections_)) {
    if (this->empties_gnuhash_) {
      this->build_empty_symbol_gnuhash();
    } else {
      this->build_symbol_gnuhash<ELF_T>();
    }
  }
}

template<typename ELF_T>
void Builder::build_dynamic_symbols(void) {

  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Sym  = typename ELF_T::Elf_Sym;
  LOG(DEBUG) << "[+] Building dynamic symbols";

  // Find useful sections
  // ====================
  uint64_t symbol_table_va = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_SYMTAB).value();
  uint64_t string_table_va = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_STRTAB).value();

  // Find the section associated with the address
  Section& symbol_table_section = this->binary_->section_from_virtual_address(symbol_table_va);
  Section& string_table_section = this->binary_->section_from_virtual_address(string_table_va);

  LOG(DEBUG) << "SYMTAB's address: 0x" << std::hex << symbol_table_va;
  LOG(DEBUG) << "SYMTAB's section: " << symbol_table_section.name().c_str();
  LOG(DEBUG) << "STRTAB's section: " << string_table_section.name().c_str();

  // Build symbols string table
  std::vector<uint8_t> string_table_raw = string_table_section.content();

  std::vector<std::string> string_table_optimized =
    this->optimize<Symbol, decltype(this->binary_->dynamic_symbols_)>(this->binary_->dynamic_symbols_);

  for (const std::string& name : string_table_optimized) {
    string_table_raw.insert(std::end(string_table_raw), std::begin(name), std::end(name));
    string_table_raw.push_back(0);
  }


  //
  // Build symbols
  //
  std::vector<uint8_t> symbol_table_raw;
  for (const Symbol* symbol : this->binary_->dynamic_symbols_) {
    const std::string& name = symbol->name();
    // Check if name is already pressent
    auto&& it_name = std::search(
        std::begin(string_table_raw),
        std::end(string_table_raw),
        name.c_str(),
        name.c_str() + name.size() + 1);

    if (it_name == std::end(string_table_raw)) {
      throw LIEF::not_found("Unable to find the symbol in the string table");
    }
    const uint64_t name_offset = static_cast<uint64_t>(std::distance(std::begin(string_table_raw), it_name));

    Elf_Sym sym_header;
    sym_header.st_name  = static_cast<Elf_Word>(name_offset);
    sym_header.st_info  = static_cast<unsigned char>(symbol->information());
    sym_header.st_other = static_cast<unsigned char>(symbol->other());
    sym_header.st_shndx = static_cast<Elf_Half>(symbol->shndx());
    sym_header.st_value = static_cast<Elf_Addr>(symbol->value());
    sym_header.st_size  = static_cast<Elf_Word>(symbol->size());

    symbol_table_raw.insert(
        std::end(symbol_table_raw),
        reinterpret_cast<uint8_t*>(&sym_header),
        reinterpret_cast<uint8_t*>(&sym_header) + sizeof(Elf_Sym));
  }

  LOG(DEBUG) << "Set raw string table";

  //string_table_section.content(string_table_raw);
  if (string_table_raw.size() <= string_table_section.size()) {
    string_table_section.content(string_table_raw);
  } else {
    //TODO
    string_table_section.content(string_table_raw);
    //LOG(DEBUG) << "New dynamic string table is bigger " << std::dec << string_table_raw.size()
    //           << " than the original one " << string_table_section.size();

    //std::pair<uint64_t, uint64_t> offset_size = this->binary_->insert_content(string_table_raw);
    //LOG(DEBUG) << "New 'dynamic string table' offset: " << std::hex << std::get<0>(offset_size);
    //LOG(DEBUG) << "New 'dynamic string table' size:   " << std::hex << std::get<1>(offset_size);

    //Section& dynamic_section = this->binary_->get_dynamic_section();

    //this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_STRTAB).value(std::get<0>(offset_size));
    //this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_STRSZ).value(std::get<1>(offset_size));


    //Section new_string_table_section;// = string_table_section;
    //new_string_table_section.content(string_table_raw);
    //Section& section_added = this->binary_->add_section(new_string_table_section, true);
  }

  LOG(DEBUG) << "Write back symbol table";

  symbol_table_section.content(symbol_table_raw);

}

template<typename ELF_T>
void Builder::build_dynamic_relocations(void) {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;
  LOG(DEBUG) << "[+] Building dynamic relocations";

  it_dynamic_relocations dynamic_relocations = this->binary_->get_dynamic_relocations();

  bool isRela = dynamic_relocations[0].is_rela();
  if (not std::all_of(
        std::begin(dynamic_relocations),
        std::end(dynamic_relocations),
        [isRela] (const Relocation& relocation) {
          return relocation.is_rela() == isRela;
        })) {
      throw LIEF::type_error("Relocation are not of the same type");
  }

  dynamic_entries_t::iterator it_dyn_relocation;
  dynamic_entries_t::iterator it_dyn_relocation_size;

  if (isRela) {
    it_dyn_relocation = std::find_if(
        std::begin(this->binary_->dynamic_entries_),
        std::end(this->binary_->dynamic_entries_),
        [] (const DynamicEntry* entry)
        {
          return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELA;
        });

    it_dyn_relocation_size = std::find_if(
        std::begin(this->binary_->dynamic_entries_),
        std::end(this->binary_->dynamic_entries_),
        [] (const DynamicEntry* entry)
        {
          return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELASZ ;
        });
  } else {
    it_dyn_relocation = std::find_if(
        std::begin(this->binary_->dynamic_entries_),
        std::end(this->binary_->dynamic_entries_),
        [] (const DynamicEntry* entry)
        {
          return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_REL;
        });

    it_dyn_relocation_size = std::find_if(
        std::begin(this->binary_->dynamic_entries_),
        std::end(this->binary_->dynamic_entries_),
        [] (const DynamicEntry* entry)
        {
          return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_RELSZ ;
        });
  }

  if (it_dyn_relocation == std::end(this->binary_->dynamic_entries_)) {
    throw LIEF::not_found("Unable to find the DT_REL{A} entry");
  }

  if (it_dyn_relocation_size == std::end(this->binary_->dynamic_entries_)) {
    throw LIEF::not_found("Unable to find the DT_REL{A}SZ entry");
  }

  Section& relocation_section = this->binary_->section_from_virtual_address((*it_dyn_relocation)->value());

  if (isRela) {
    (*it_dyn_relocation_size)->value(dynamic_relocations.size() * sizeof(Elf_Rela));
  } else {
    (*it_dyn_relocation_size)->value(dynamic_relocations.size() * sizeof(Elf_Rel));
  }

  std::vector<uint8_t> content;
  for (const Relocation& relocation : this->binary_->get_dynamic_relocations()) {

    // look for symbol index
    uint32_t idx = 0;
    if (relocation.has_symbol()) {
      const Symbol& symbol    = relocation.symbol();
      const std::string& name = symbol.name();
      auto&& it_name  = std::find_if(
          std::begin(this->binary_->dynamic_symbols_),
          std::end(this->binary_->dynamic_symbols_),
          [&name] (const Symbol* s) {
            return s->name() == name;
          });

      if (it_name == std::end(this->binary_->dynamic_symbols_)) {
        throw not_found("Unable to find the symbol associated with the relocation");
      }

      idx = static_cast<uint32_t>(std::distance(std::begin(this->binary_->dynamic_symbols_), it_name));
    }


    Elf_Xword info = 0;
    if (std::is_same<ELF_T, ELF32>::value) {
      info = (static_cast<Elf_Xword>(idx) << 8) | relocation.type();
    } else {
      info = (static_cast<Elf_Xword>(idx) << 32) | (relocation.type() & 0xffffffffL);
    }

    if (isRela) {
      Elf_Rela relahdr;
      relahdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relahdr.r_info   = static_cast<Elf_Xword>(info);
      relahdr.r_addend = static_cast<Elf_Sxword>(relocation.addend());

      content.insert(
          std::end(content),
          reinterpret_cast<uint8_t*>(&relahdr),
          reinterpret_cast<uint8_t*>(&relahdr) + sizeof(Elf_Rela));

    } else {
      Elf_Rel relhdr;
      relhdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relhdr.r_info   = static_cast<Elf_Xword>(info);

      content.insert(
          std::end(content),
          reinterpret_cast<uint8_t*>(&relhdr),
          reinterpret_cast<uint8_t*>(&relhdr) + sizeof(Elf_Rel));
    }

  }

  relocation_section.content(content);
}

template<typename ELF_T>
void Builder::build_pltgot_relocations(void) {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;

  LOG(DEBUG) << "[+] Building .plt.got relocations";

  it_pltgot_relocations pltgot_relocations = this->binary_->get_pltgot_relocations();

  bool isRela = pltgot_relocations[0].is_rela();

  if (not std::all_of(
        std::begin(pltgot_relocations),
        std::end(pltgot_relocations),
        [isRela] (const Relocation& relocation) {
          return relocation.is_rela() == isRela;
        })) {
      throw LIEF::type_error("Relocation are not of the same type");
  }

  //TODO: check DT_PLTREL
  auto&& it_dyn_relocation = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_JMPREL;
      });

  auto&& it_dyn_relocation_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PLTRELSZ;
      });

  if (it_dyn_relocation == std::end(this->binary_->dynamic_entries_)) {
    throw LIEF::not_found("Unable to find the DT_JMPREL entry");
  }

  if (it_dyn_relocation_size == std::end(this->binary_->dynamic_entries_)) {
    throw LIEF::not_found("Unable to find the DT_PLTRELSZ entry");
  }

  Section& relocation_section = this->binary_->section_from_virtual_address((*it_dyn_relocation)->value());
  if (isRela) {
    (*it_dyn_relocation_size)->value(pltgot_relocations.size() * sizeof(Elf_Rela));
  } else {
    (*it_dyn_relocation_size)->value(pltgot_relocations.size() * sizeof(Elf_Rel));
  }

  std::vector<uint8_t> content; // Section's content
  for (const Relocation& relocation : this->binary_->get_pltgot_relocations()) {


    uint32_t idx = 0;
    if (relocation.has_symbol()) {
      // look for symbol index
      const Symbol& symbol = relocation.symbol();
      const std::string& name = symbol.name();
      auto&& it_name = std::find_if(
          std::begin(this->binary_->dynamic_symbols_),
          std::end(this->binary_->dynamic_symbols_),
          [&name] (const Symbol* s) {
            return s->name() == name;
          });

      if (it_name == std::end(this->binary_->dynamic_symbols_)) {
        throw not_found("Unable to find the symbol associated with the relocation");
      }

      idx = static_cast<uint32_t>(std::distance(std::begin(this->binary_->dynamic_symbols_), it_name));
    }

    Elf_Xword info = 0;
    if (std::is_same<ELF_T, ELF32>::value) {
      info = (static_cast<Elf_Xword>(idx) << 8) | relocation.type();
    } else {
      info = (static_cast<Elf_Xword>(idx) << 32) | (relocation.type() & 0xffffffffL);
    }

    if (isRela) {
      Elf_Rela relahdr;
      relahdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relahdr.r_info   = static_cast<Elf_Xword>(info);
      relahdr.r_addend = static_cast<Elf_Sxword>(relocation.addend());

      content.insert(
          std::end(content),
          reinterpret_cast<uint8_t*>(&relahdr),
          reinterpret_cast<uint8_t*>(&relahdr) + sizeof(Elf_Rela));

    } else {
      Elf_Rel relhdr;
      relhdr.r_offset = static_cast<Elf_Addr>(relocation.address());
      relhdr.r_info   = static_cast<Elf_Xword>(info);

      content.insert(
          std::end(content),
          reinterpret_cast<uint8_t*>(&relhdr),
          reinterpret_cast<uint8_t*>(&relhdr) + sizeof(Elf_Rel));
    }
  }

  relocation_section.content(content);
}


template<typename ELF_T>
void Builder::build_symbol_requirement(void) {
  using Elf_Half    = typename ELF_T::Elf_Half;
  using Elf_Word    = typename ELF_T::Elf_Word;
  using Elf_Word    = typename ELF_T::Elf_Word;

  using Elf_Verneed = typename ELF_T::Elf_Verneed;
  using Elf_Vernaux = typename ELF_T::Elf_Vernaux;
  LOG(DEBUG) << "[+] Building symbol requirement";


  const uint64_t svr_address = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_VERNEED).value();
  const uint64_t svr_offset  = this->binary_->virtual_address_to_offset(svr_address);
  const uint64_t svr_nb      = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_VERNEEDNUM).value();

  if (svr_nb != this->binary_->symbol_version_requirements_.size()) {
    LOG(WARNING) << "The number of symbol version requirement \
      entries in the binary differ from the value in DT_VERNEEDNUM";
  }

  const uint64_t dyn_str_va = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_STRTAB).value();

  Section& dyn_str_section = this->binary_->section_from_virtual_address(dyn_str_va);
  std::vector<uint8_t> svr_raw;
  std::vector<uint8_t> dyn_str_raw = dyn_str_section.content();

  uint32_t svr_idx = 0;
  for (const SymbolVersionRequirement& svr: this->binary_->get_symbols_version_requirement()) {
    const std::string& name = svr.name();
    auto&& it_name_offset  = std::search(
        std::begin(dyn_str_raw),
        std::end(dyn_str_raw),
        name.c_str(),
        name.c_str() + name.size() + 1);

    uint64_t name_offset = 0;

    if (it_name_offset != std::end(dyn_str_raw)) {
      name_offset = static_cast<uint64_t>(std::distance(std::begin(dyn_str_raw), it_name_offset));
    } else {
      LOG(DEBUG) << "[LIEF_DEBUG] buildSymbolRequirement(): Library name is not present";
      dyn_str_raw.insert(std::end(dyn_str_raw), std::begin(name), std::end(name));
      dyn_str_raw.push_back(0);
      name_offset = dyn_str_raw.size() - name.size() - 1;
    }

    it_const_symbols_version_aux_requirement svars = svr.get_auxiliary_symbols();

    uint64_t next_symbol_offset = 0;
    if (svr_idx < (this->binary_->symbol_version_requirements_.size() - 1)) {
      next_symbol_offset = sizeof(Elf_Verneed) + svars.size() * sizeof(Elf_Vernaux);
    }

    Elf_Verneed header;
    header.vn_version = static_cast<Elf_Half>(svr.version());
    header.vn_cnt     = static_cast<Elf_Half>(svars.size());
    header.vn_file    = static_cast<Elf_Word>(name_offset);
    header.vn_aux     = static_cast<Elf_Word>(svars.size() > 0 ? sizeof(Elf_Verneed) : 0);
    header.vn_next    = static_cast<Elf_Word>(next_symbol_offset);

    svr_raw.insert(
        std::end(svr_raw),
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(Elf_Verneed));


    uint32_t svar_idx = 0;
    for (const SymbolVersionAuxRequirement& svar : svars) {
      const std::string& svar_name = svar.name();
      auto&& it_svar_name_offset = std::search(
          std::begin(dyn_str_raw),
          std::end(dyn_str_raw),
          svar_name.c_str(),
          svar_name.c_str() + svar_name.size() + 1);

      uint64_t svar_name_offset = 0;

      if (it_svar_name_offset != std::end(dyn_str_raw)) {
        svar_name_offset = static_cast<uint64_t>(std::distance(std::begin(dyn_str_raw), it_svar_name_offset));
      } else {
        dyn_str_raw.insert(std::end(dyn_str_raw), std::begin(svar_name), std::end(svar_name));
        dyn_str_raw.push_back(0);
        svar_name_offset = dyn_str_raw.size() - svar_name.size() - 1;
      }

      Elf_Vernaux aux_header;
      aux_header.vna_hash  = static_cast<Elf_Word>(svar.hash());
      aux_header.vna_flags = static_cast<Elf_Half>(svar.flags());
      aux_header.vna_other = static_cast<Elf_Half>(svar.other());
      aux_header.vna_name  = static_cast<Elf_Word>(svar_name_offset);
      aux_header.vna_next  = static_cast<Elf_Word>(svar_idx < (svars.size() - 1) ? sizeof(Elf_Vernaux) : 0);

      svr_raw.insert(
          std::end(svr_raw),
          reinterpret_cast<uint8_t*>(&aux_header),
          reinterpret_cast<uint8_t*>(&aux_header) + sizeof(Elf_Vernaux));

      ++svar_idx;
    }

    ++svr_idx;
  }

  this->binary_->section_from_offset(svr_offset).content(svr_raw);
  dyn_str_section.content(dyn_str_raw);

}

template<typename ELF_T>
void Builder::build_symbol_definition(void) {
  using Elf_Half   = typename ELF_T::Elf_Half;
  using Elf_Word   = typename ELF_T::Elf_Word;
  using Elf_Word   = typename ELF_T::Elf_Word;

  using Elf_Verdef   = typename ELF_T::Elf_Verdef;
  using Elf_Verdaux   = typename ELF_T::Elf_Verdaux;

  LOG(DEBUG) << "[+] Building symbol definition";

  const uint64_t svd_va     = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_VERDEF).value();
  const uint64_t svd_offset = this->binary_->virtual_address_to_offset(svd_va);
  const uint64_t svd_nb     = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_VERDEFNUM).value();

  if (svd_nb != this->binary_->symbol_version_definition_.size()) {
    LOG(WARNING) << "The number of symbol version definition entries\
      in the binary differ from the value in DT_VERDEFNUM";
  }


  const uint64_t dyn_str_va = this->binary_->dynamic_entry_from_tag(DYNAMIC_TAGS::DT_STRTAB).value();
  Section& dyn_str_section = this->binary_->section_from_virtual_address(dyn_str_va);

  std::vector<uint8_t> svd_raw;
  std::vector<uint8_t> dyn_str_raw = dyn_str_section.content();

  uint32_t svd_idx = 0;
  for (const SymbolVersionDefinition& svd: this->binary_->get_symbols_version_definition()) {

    it_const_symbols_version_aux svas = svd.symbols_aux();

    uint64_t next_symbol_offset = 0;

    if (svd_idx < (svd_nb - 1)) {
      next_symbol_offset = sizeof(Elf_Verdef) + svas.size() * sizeof(Elf_Verdaux);
    }

    Elf_Verdef header;
    header.vd_version = static_cast<Elf_Half>(svd.version());
    header.vd_flags   = static_cast<Elf_Half>(svd.flags());
    header.vd_ndx     = static_cast<Elf_Half>(svd.ndx());
    header.vd_cnt     = static_cast<Elf_Half>(svas.size());
    header.vd_hash    = static_cast<Elf_Word>(svd.hash());
    header.vd_aux     = static_cast<Elf_Word>(svas.size() > 0 ? sizeof(Elf_Verdef) : 0);
    header.vd_next    = static_cast<Elf_Word>(next_symbol_offset);

    svd_raw.insert(std::end(svd_raw),
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(Elf_Verdef));


    uint32_t sva_idx = 0;
    for (const SymbolVersionAux& sva : svas) {
      const std::string& sva_name = sva.name();
      auto&& it_sva_name_offset = std::search(
          std::begin(dyn_str_raw),
          std::end(dyn_str_raw),
          sva_name.c_str(),
          sva_name.c_str() + sva_name.size() + 1);

      uint64_t sva_name_offset = 0;

      if (it_sva_name_offset != std::end(dyn_str_raw)) {
        sva_name_offset = static_cast<uint64_t>(std::distance(std::begin(dyn_str_raw), it_sva_name_offset));
      } else {
        dyn_str_raw.insert(std::end(dyn_str_raw), std::begin(sva_name), std::end(sva_name));
        dyn_str_raw.push_back(0);
        sva_name_offset = dyn_str_raw.size() - sva_name.size() - 1;
      }


      Elf_Verdaux aux_header;
      aux_header.vda_name  = static_cast<Elf_Word>(sva_name_offset);
      aux_header.vda_next  = static_cast<Elf_Word>(sva_idx < (svas.size() - 1) ? sizeof(Elf_Verdaux) : 0);

      svd_raw.insert(
          std::end(svd_raw),
          reinterpret_cast<uint8_t*>(&aux_header),
          reinterpret_cast<uint8_t*>(&aux_header) + sizeof(Elf_Verdaux));

      ++sva_idx;
    }
    ++svd_idx;
  }


  this->binary_->section_from_offset(svd_offset).content(svd_raw);
  dyn_str_section.content(dyn_str_raw);

}
}
}
