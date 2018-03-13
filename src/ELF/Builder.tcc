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

#include "LIEF/logging++.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/EnumToString.hpp"

#include "Object.tcc"

namespace LIEF {
namespace ELF {

template<class ELF_T>
void Builder::build(void) {


  std::string type = ((this->binary_->type_ == ELF_CLASS::ELFCLASS32) ? "ELF32" : "ELF64");
  VLOG(VDEBUG) << "== Re-building " << type << " ==";
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


  // Build Relocations
  if (this->binary_->dynamic_relocations().size() > 0) {
    try {
      this->build_dynamic_relocations<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  if (this->binary_->pltgot_relocations().size() > 0) {
    try {
      this->build_pltgot_relocations<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }


  // Build symbols version
  if (this->binary_->symbol_version_table_.size() > 0) {
    try {
      this->build_symbol_version<ELF_T>();
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

  // Build static symbols
  if (this->binary_->static_symbols_.size() > 0) {
    try {
      this->build_static_symbols<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }


  // Build Interpreter
  if (this->binary_->has_interpreter()) {
    try {
      this->build_interpreter<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  // Build Notes
  if (this->binary_->has_notes()) {
    try {
      this->build_notes<ELF_T>();
    } catch (const LIEF::exception& e) {
      LOG(ERROR) << e.what();
    }
  }


  // Build sections
  this->build_sections<ELF_T>();

  // Build PHDR
  if (this->binary_->header().program_headers_offset() > 0) {
    this->build_segments<ELF_T>();
  } else {
    LOG(WARNING) << "Segments offset is null";
  }

  this->build<ELF_T>(this->binary_->header());

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
void Builder::build(const Header& header) {;
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Ehdr = typename ELF_T::Elf_Ehdr;

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
  VLOG(VDEBUG) << "[+] Build sections";

  const Header& header = this->binary_->header();
  const Elf_Off section_headers_offset = header.section_headers_offset();

  std::vector<std::string> stringTableOpti =
    this->optimize<Section, decltype(this->binary_->sections_)>(this->binary_->sections_);

  // Build section's name
  std::vector<uint8_t> section_names;
  section_names.push_back(0);
  for (const std::string& name : stringTableOpti) {
    section_names.insert(std::end(section_names), std::begin(name), std::end(name));
    section_names.push_back(0);
  }

  Section* string_names_section = this->binary_->sections_[header.section_name_table_idx()];
  string_names_section->content(section_names);

  // **Should** be safe since .shstr is located at the end of the binary
  //if (string_names_section->size() < section_names.size()) {
  // string_names_section = &(this->binary_->extend_section(*string_names_section, section_names.size() - string_names_section->size() + 1));
  //}

  for (size_t i = 0; i < this->binary_->sections_.size(); i++) {
    const Section* section = this->binary_->sections_[i];
    VLOG(VDEBUG) << "Writing back '" << section->name() << "'";

    auto&& it_offset_name = std::search(
        std::begin(section_names),
        std::end(section_names),
        section->name().c_str(),
        section->name().c_str() + section->name().size() + 1);

    if (it_offset_name == std::end(section_names)) {
      throw LIEF::not_found(""); // TODO: msg
    }


    // Write Section's content
    if (section->size() > 0) {
      this->ios_.seekp(section->file_offset());
      this->ios_.write(section->content());
    }
  }

  for (size_t i = 0; i < this->binary_->sections_.size(); i++) {
    const Section* section = this->binary_->sections_[i];
    VLOG(VDEBUG) << "Writing back '" << section->name() << "'";

    auto&& it_offset_name = std::search(
        std::begin(section_names),
        std::end(section_names),
        section->name().c_str(),
        section->name().c_str() + section->name().size() + 1);

    if (it_offset_name == std::end(section_names)) {
      throw LIEF::not_found(""); // TODO: msg
    }

    const Elf_Off offset_name = static_cast<Elf_Off>(std::distance(std::begin(section_names), it_offset_name));

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
  }

  this->ios_.seekp(string_names_section->file_offset());
  this->ios_.write(std::move(section_names));


}


template<typename ELF_T>
void Builder::build_segments(void) {
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Phdr = typename ELF_T::Elf_Phdr;
  VLOG(VDEBUG) << "[+] Build segments";

  std::vector<uint8_t> pheaders;
  pheaders.reserve(this->binary_->segments_.size() * sizeof(Elf_Phdr));

  for (const Segment* segment : this->binary_->segments_) {
      Elf_Phdr phdr;
      phdr.p_type   = static_cast<Elf_Word>(segment->type());
      phdr.p_flags  = static_cast<Elf_Word>(segment->flags());
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
  }


  // Write segment content
  for (const Segment* segment : this->binary_->segments_) {
    if (segment->physical_size() > 0) {
      const std::vector<uint8_t>& content = segment->content();
      VLOG(VDEBUG) << "Write content for segment " << *segment;
      VLOG(VDEBUG) << "Offset: 0x" << std::hex << segment->file_offset();
      VLOG(VDEBUG) << "Size: 0x" << std::hex << content.size();

      this->ios_.seekp(segment->file_offset());
      this->ios_.write(std::move(content));
    }
  }

  const Elf_Off segment_header_offset = this->binary_->header().program_headers_offset();
  this->ios_.seekp(segment_header_offset);
  this->ios_.write(std::move(pheaders));
}


template<typename ELF_T>
void Builder::build_static_symbols(void) {
  using Elf_Half = typename ELF_T::Elf_Half;
  using Elf_Word = typename ELF_T::Elf_Word;
  using Elf_Addr = typename ELF_T::Elf_Addr;
  using Elf_Off  = typename ELF_T::Elf_Off;

  using Elf_Sym  = typename ELF_T::Elf_Sym;
  VLOG(VDEBUG) << "Build static symbols";

  Section& symbol_section = this->binary_->static_symbols_section();
  VLOG(VDEBUG) << "Section: " << symbol_section << std::endl;

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
    VLOG(VDEBUG) << "Dealing with symbol: " << symbol->name();
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

    const Elf_Off name_offset = static_cast<Elf_Off>(std::distance(std::begin(string_table), it_name));

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

  symbol_str_section.content(std::move(string_table));
  symbol_section.content(std::move(content));

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
  VLOG(VDEBUG) << "Building dynamic part";

  if (this->binary_->dynamic_entries_.size() > 0) {
    this->build_dynamic_section<ELF_T>();
  }

  if (this->binary_->dynamic_symbols_.size() > 0) {
    this->build_dynamic_symbols<ELF_T>();
  }
}

template<typename ELF_T>
void Builder::build_dynamic_section(void) {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;
  using Elf_Xword  = typename ELF_T::Elf_Xword;

  using Elf_Dyn    = typename ELF_T::Elf_Dyn;

  VLOG(VDEBUG) << "[+] Building dynamic section";

  const Elf_Addr dyn_strtab_va = this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value();

  Section& dyn_strtab_section = this->binary_->section_from_virtual_address(dyn_strtab_va);
  Section& dyn_section        = this->binary_->dynamic_section();

  std::vector<uint8_t> dynamic_strings_raw;
  std::vector<uint8_t> dynamic_table_raw;
  dynamic_strings_raw.push_back(0);

  for (DynamicEntry* entry : this->binary_->dynamic_entries_) {

    switch (entry->tag()) {
      case DYNAMIC_TAGS::DT_NEEDED:
        {
          const std::string& name = entry->as<DynamicEntryLibrary>()->name();
          dynamic_strings_raw.insert(
              std::end(dynamic_strings_raw),
              std::begin(name),
              std::end(name));
          dynamic_strings_raw.push_back(0);
          entry->value(dynamic_strings_raw.size() - (name.size() + 1));
          break;
        }

      case DYNAMIC_TAGS::DT_SONAME:
        {
          const std::string& name = entry->as<DynamicSharedObject>()->name();
          dynamic_strings_raw.insert(
              std::end(dynamic_strings_raw),
              std::begin(name),
              std::end(name));
          dynamic_strings_raw.push_back(0);
          entry->value(dynamic_strings_raw.size() - (name.size() + 1));
          break;
        }

      case DYNAMIC_TAGS::DT_RPATH:
        {
          const std::string& name = entry->as<DynamicEntryRpath>()->name();
          dynamic_strings_raw.insert(
              std::end(dynamic_strings_raw),
              std::begin(name),
              std::end(name));
          dynamic_strings_raw.push_back(0);
          entry->value(dynamic_strings_raw.size() - (name.size() + 1));
          break;
        }

      case DYNAMIC_TAGS::DT_RUNPATH:
        {
          const std::string& name = entry->as<DynamicEntryRunPath>()->name();
          dynamic_strings_raw.insert(
              std::end(dynamic_strings_raw),
              std::begin(name),
              std::end(name));
          dynamic_strings_raw.push_back(0);
          entry->value(dynamic_strings_raw.size() - (name.size() + 1));
          break;
        }


      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          const Elf_Addr address = entry->value();

          DynamicEntry* dt_array_size = nullptr;
          switch (entry->tag()) {
            case DYNAMIC_TAGS::DT_FINI_ARRAY:
              {
                dt_array_size = &(this->binary_->get(DYNAMIC_TAGS::DT_FINI_ARRAYSZ));
                break;
              }
            case DYNAMIC_TAGS::DT_INIT_ARRAY:
              {
                dt_array_size = &(this->binary_->get(DYNAMIC_TAGS::DT_INIT_ARRAYSZ));
                break;
              }

            case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
              {
                dt_array_size = &(this->binary_->get(DYNAMIC_TAGS::DT_PREINIT_ARRAYSZ));
                break;
              }

            default:
              {
              }
          }

          if (dt_array_size == nullptr) {
            throw not_found(std::string("Unable to find the 'DT_ARRAYSZ' associated with ") + to_string(entry->tag()));
          }

          Section& array_section = this->binary_->section_from_virtual_address(address);

          const std::vector<uint64_t>& array = entry->as<DynamicEntryArray>()->array();
          const size_t array_size = array.size() * sizeof(Elf_Addr);


          if (array_section.original_size() < array_size) {
            this->relocate_dynamic_array<ELF_T>(*dynamic_cast<DynamicEntryArray*>(entry), *dt_array_size);
            return build_dynamic_section<ELF_T>();
          }

          std::vector<uint8_t> array_content(array_size, 0);

          Elf_Addr* raw_array = reinterpret_cast<Elf_Addr*>(array_content.data());
          for(size_t i = 0; i < array.size(); ++i) {
            raw_array[i] = static_cast<Elf_Addr>(array[i]);
          }

          dt_array_size->value((array.size()) * sizeof(Elf_Addr));
          array_section.content(array_content);
          break;
        }

      default:
        {
        }
    }

    Elf_Dyn dynhdr;
    dynhdr.d_tag       = static_cast<Elf_Sxword>(entry->tag());
    dynhdr.d_un.d_val  = static_cast<Elf_Xword>(entry->value());

    dynamic_table_raw.insert(
      std::end(dynamic_table_raw),
      reinterpret_cast<uint8_t*>(&dynhdr),
      reinterpret_cast<uint8_t*>(&dynhdr) + sizeof(Elf_Dyn));
  }


  if (dynamic_table_raw.size() > dyn_section.original_size()) {
    VLOG(VDEBUG) << "Need to relocate the '.dynamic' section";
    VLOG(VDEBUG) << std::dec << dynamic_table_raw.size() <<  " > " << dyn_section.original_size();

    // Create a LOAD segment for the new Dynamic:
    Segment dynamic_load;
    dynamic_load.type(SEGMENT_TYPES::PT_LOAD);
    dynamic_load.flags(ELF_SEGMENT_FLAGS::PF_R | ELF_SEGMENT_FLAGS::PF_W);
    dynamic_load.content(dynamic_table_raw);
    Segment& new_dynamic_load = this->binary_->add(dynamic_load);

    auto&& it_dynamic = std::find_if(
        std::begin(this->binary_->segments_),
        std::end(this->binary_->segments_),
        [] (const Segment* s) {
          return s->type() == SEGMENT_TYPES::PT_DYNAMIC;
        });
    Segment* dynamic_segment = *it_dynamic;

    dynamic_segment->virtual_address(new_dynamic_load.virtual_address());
    dynamic_segment->virtual_size(new_dynamic_load.virtual_size());
    dynamic_segment->physical_address(new_dynamic_load.physical_address());

    dynamic_segment->file_offset(new_dynamic_load.file_offset());
    dynamic_segment->physical_size(new_dynamic_load.physical_size());

    dyn_section.virtual_address(new_dynamic_load.virtual_address());
    dyn_section.size(new_dynamic_load.physical_size());
    dyn_section.offset(new_dynamic_load.file_offset());
    dyn_section.content(new_dynamic_load.content());
    dyn_section.original_size_ = new_dynamic_load.physical_size();

    return this->build_dynamic<ELF_T>();

  }

  if (dynamic_strings_raw.size() > dyn_strtab_section.original_size()) {

    VLOG(VDEBUG) << "Need to relocate the '.dynstr' section";
    VLOG(VDEBUG) << std::dec << dynamic_strings_raw.size() <<  " > " << dyn_strtab_section.size();

    // Create a segment:
    Segment dynstr;
    dynstr.type(SEGMENT_TYPES::PT_LOAD);
    dynstr.flags(ELF_SEGMENT_FLAGS::PF_R);
    dynstr.content(dynamic_strings_raw);

    Segment& new_segment = this->binary_->add(dynstr);
    dyn_strtab_section.virtual_address(new_segment.virtual_address());
    dyn_strtab_section.size(new_segment.physical_size());
    dyn_strtab_section.offset(new_segment.file_offset());
    dyn_strtab_section.content(new_segment.content());
    dyn_strtab_section.original_size_ = new_segment.physical_size();

    VLOG(VDEBUG) << std::dec << "New '.dynstr' size: " << dyn_strtab_section.size();

    this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value(new_segment.virtual_address());
    this->binary_->get(DYNAMIC_TAGS::DT_STRSZ).value(dynamic_strings_raw.size());

    return this->build_dynamic<ELF_T>();
  }

  VLOG(VDEBUG) << dyn_strtab_section;
  dyn_strtab_section.content(std::move(dynamic_strings_raw));
  dyn_section.content(std::move(dynamic_table_raw));
}


template<typename ELF_T>
void Builder::build_symbol_hash(void) {
  VLOG(VDEBUG) << "Build SYSV Hash ";
  auto&& it_hash_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_HASH;
      });

  if (it_hash_section == std::end(this->binary_->sections_)) {
    return;
  }

  std::vector<uint8_t> content = (*it_hash_section)->content();
  VectorStream hashtable_stream{content};

  uint32_t nbucket = hashtable_stream.read_integer<uint32_t>(0);
  uint32_t nchain  = hashtable_stream.read_integer<uint32_t>(0 + sizeof(uint32_t));


  std::vector<uint8_t> new_hash_table((nbucket + nchain + 2) * sizeof(uint32_t), 0);
  uint32_t *new_hash_table_ptr = reinterpret_cast<uint32_t*>(new_hash_table.data());

  new_hash_table_ptr[0] = nbucket;
  new_hash_table_ptr[1] = nchain;

  uint32_t* bucket = &new_hash_table_ptr[2];
  uint32_t* chain  = &new_hash_table_ptr[2 + nbucket];
  uint32_t idx = 0;
  for (const Symbol* symbol : this->binary_->dynamic_symbols_) {
    uint32_t hash = 0;

    if (this->binary_->type_ == ELF_CLASS::ELFCLASS32) {
      hash = hash32(symbol->name().c_str());
    } else {
      hash = hash64(symbol->name().c_str());
    }

    if(bucket[hash % nbucket] == 0) {
      bucket[hash % nbucket] = idx;
    } else {
      uint32_t value = bucket[hash % nbucket];
      while (chain[value] != 0) {
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

  Section& h_section = **it_hash_section;
  if (new_hash_table.size() > h_section.size()) {
    LOG(INFO) << "Need to relocate the '" << h_section.name() << "' section";

    VLOG(VDEBUG) << std::dec << new_hash_table.size() <<  " > " << h_section.size();

    Segment syvhash;
    syvhash.type(SEGMENT_TYPES::PT_LOAD);
    syvhash.flags(ELF_SEGMENT_FLAGS::PF_R);
    syvhash.content(new_hash_table);

    Segment& new_segment = this->binary_->add(syvhash);

    h_section.virtual_address(new_segment.virtual_address());
    h_section.size(new_segment.physical_size());
    h_section.offset(new_segment.file_offset());
    h_section.content(new_segment.content());

    h_section.original_size_ = new_segment.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_HASH).value(new_segment.virtual_address());
    return this->build<ELF_T>();
  }

  h_section.content(std::move(new_hash_table));
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

  VLOG(VDEBUG) << "Rebuild GNU Hash table";

  const GnuHash& gnu_hash   = this->binary_->gnu_hash();

  const uint32_t nb_buckets = gnu_hash.nb_buckets();
  const uint32_t symndx     = gnu_hash.symbol_index();
  const uint32_t maskwords  = gnu_hash.maskwords();
  const uint32_t shift2     = gnu_hash.shift2();

  VLOG(VDEBUG) << "Number of buckets " << std::dec << nb_buckets;
  VLOG(VDEBUG) << "First symbol idx  " << std::dec << symndx;
  VLOG(VDEBUG) << "Number of bloom filters  " << std::dec << maskwords;
  VLOG(VDEBUG) << "Shift  " << std::dec << shift2;

  // MANDATORY !
  std::stable_sort(
      std::begin(this->binary_->dynamic_symbols_) + symndx,
      std::end(this->binary_->dynamic_symbols_),
      [&nb_buckets] (const Symbol* lhs, const Symbol* rhs) {
        return
          (dl_new_hash(lhs->name().c_str()) % nb_buckets) <
          (dl_new_hash(rhs->name().c_str()) % nb_buckets);
    });

  it_symbols dynamic_symbols = this->binary_->dynamic_symbols();

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
    VLOG(VDEBUG) << "Bloom filter [" << std::dec << idx << "]: " << std::hex << bloom_filters[idx];
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
    VLOG(VDEBUG) << "Dealing with symbol " << dynamic_symbols[i];
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
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_GNU_HASH;
      });

  if (it_gnuhash == std::end(this->binary_->sections_)) {
    throw corrupted("Unable to find the .gnu.hash section");
  }

  Section& h_section = **it_gnuhash;
  if (raw_gnuhash.size() > h_section.size()) {
    LOG(INFO) << "Need to relocate the '" << h_section.name() << "' section";

    VLOG(VDEBUG) << std::dec << raw_gnuhash.size() <<  " > " << h_section.size();

    Segment gnuhash;
    gnuhash.type(SEGMENT_TYPES::PT_LOAD);
    gnuhash.flags(ELF_SEGMENT_FLAGS::PF_R);
    gnuhash.content(raw_gnuhash);

    Segment& new_segment = this->binary_->add(gnuhash);

    h_section.virtual_address(new_segment.virtual_address());
    h_section.size(new_segment.physical_size());
    h_section.offset(new_segment.file_offset());
    h_section.content(new_segment.content());

    h_section.original_size_ = new_segment.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_GNU_HASH).value(new_segment.virtual_address());
    return this->build<ELF_T>();
  }


  return h_section.content(std::move(raw_gnuhash));

}

template<typename ELF_T>
void Builder::build_hash_table(void) {
  VLOG(VDEBUG) << "Build hash table";
  auto&& it_hash = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_HASH;
      });


  auto&& it_gnuhash = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_GNU_HASH;
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
  using Elf_Off  = typename ELF_T::Elf_Off;
  using Elf_Word = typename ELF_T::Elf_Word;

  using Elf_Sym  = typename ELF_T::Elf_Sym;
  VLOG(VDEBUG) << "[+] Building dynamic symbols";

  // Find useful sections
  // ====================
  Elf_Addr symbol_table_va = this->binary_->get(DYNAMIC_TAGS::DT_SYMTAB).value();
  Elf_Addr string_table_va = this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value();

  // Find the section associated with the address
  Section& symbol_table_section = this->binary_->section_from_virtual_address(symbol_table_va);
  Section& string_table_section = this->binary_->section_from_virtual_address(string_table_va);

  VLOG(VDEBUG) << "SYMTAB's address: 0x" << std::hex << symbol_table_va;
  VLOG(VDEBUG) << "SYMTAB's section: " << symbol_table_section.name().c_str();
  VLOG(VDEBUG) << "STRTAB's section: " << string_table_section.name().c_str();

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
    const Elf_Off name_offset = static_cast<Elf_Off>(std::distance(std::begin(string_table_raw), it_name));

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

  VLOG(VDEBUG) << "Set raw string table";

  // Relocation .dynstr section
  if (string_table_raw.size() > string_table_section.original_size()) {
    LOG(INFO) << "Need to relocate the '" << string_table_section.name() << "' section";
    VLOG(VDEBUG) << std::dec << string_table_raw.size() <<  " > " << string_table_section.size();

    Segment dynstr;
    dynstr.type(SEGMENT_TYPES::PT_LOAD);
    dynstr.flags(ELF_SEGMENT_FLAGS::PF_R);
    dynstr.content(string_table_raw);

    Segment& new_segment = this->binary_->add(dynstr);

    string_table_section.virtual_address(new_segment.virtual_address());
    string_table_section.size(new_segment.physical_size());
    string_table_section.offset(new_segment.file_offset());
    string_table_section.content(new_segment.content());

    string_table_section.original_size_ = new_segment.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value(new_segment.virtual_address());
    this->binary_->get(DYNAMIC_TAGS::DT_STRSZ).value(string_table_raw.size());
    return this->build_dynamic<ELF_T>();
  }

  // Relocation the .dynsym section
  if (symbol_table_raw.size() > symbol_table_section.original_size()) {
    LOG(INFO) << "Need to relocate the '" << symbol_table_section.name() << "' section";

    Segment dynsym_load;
    dynsym_load.type(SEGMENT_TYPES::PT_LOAD);
    dynsym_load.flags(ELF_SEGMENT_FLAGS::PF_R | ELF_SEGMENT_FLAGS::PF_W);
    dynsym_load.content(symbol_table_raw);
    Segment& new_dynsym_load = this->binary_->add(dynsym_load);

    symbol_table_section.virtual_address(new_dynsym_load.virtual_address());
    symbol_table_section.size(new_dynsym_load.physical_size());
    symbol_table_section.offset(new_dynsym_load.file_offset());
    symbol_table_section.content(new_dynsym_load.content());

    symbol_table_section.original_size_ = new_dynsym_load.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_STRSZ).value(symbol_table_raw.size());
    this->binary_->get(DYNAMIC_TAGS::DT_SYMTAB).value(new_dynsym_load.virtual_address());

    return this->build_dynamic<ELF_T>();
  }

  VLOG(VDEBUG) << "Write back symbol table";
  string_table_section.content(std::move(string_table_raw));
  symbol_table_section.content(std::move(symbol_table_raw));

}

template<typename ELF_T>
void Builder::build_dynamic_relocations(void) {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;
  VLOG(VDEBUG) << "[+] Building dynamic relocations";

  it_dynamic_relocations dynamic_relocations = this->binary_->dynamic_relocations();

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


  DynamicEntry* dt_reloc_addr = *it_dyn_relocation;
  DynamicEntry* dt_reloc_size = *it_dyn_relocation_size;

  Section& relocation_section = this->binary_->section_from_virtual_address(dt_reloc_addr->value());

  if (isRela) {
    dt_reloc_size->value(dynamic_relocations.size() * sizeof(Elf_Rela));
  } else {
    dt_reloc_size->value(dynamic_relocations.size() * sizeof(Elf_Rel));
  }

  std::vector<uint8_t> content;
  for (const Relocation& relocation : this->binary_->dynamic_relocations()) {

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

  VLOG(VDEBUG) << "Section associated with dynamic relocations: " << relocation_section.name();
  VLOG(VDEBUG) << "Is Rela: " << std::boolalpha << isRela;
  // Relocation the '.dyn.rel' section
  if (content.size() > relocation_section.original_size()) {
    // Need relocation of the reloc section
    Segment relocation_load;
    relocation_load.type(SEGMENT_TYPES::PT_LOAD);
    relocation_load.flags(ELF_SEGMENT_FLAGS::PF_R | ELF_SEGMENT_FLAGS::PF_W);
    relocation_load.content(content);
    Segment& new_relocation_load = this->binary_->add(relocation_load);

    relocation_section.virtual_address(new_relocation_load.virtual_address());
    relocation_section.size(new_relocation_load.physical_size());
    relocation_section.offset(new_relocation_load.file_offset());
    relocation_section.content(new_relocation_load.content());

    relocation_section.original_size_ = new_relocation_load.physical_size();

    dt_reloc_addr->value(new_relocation_load.virtual_address());
    dt_reloc_size->value(content.size());

    return this->build<ELF_T>();

  }

  relocation_section.content(std::move(content));
}

template<typename ELF_T>
void Builder::build_pltgot_relocations(void) {
  using Elf_Addr   = typename ELF_T::Elf_Addr;
  using Elf_Xword  = typename ELF_T::Elf_Xword;
  using Elf_Sxword = typename ELF_T::Elf_Sxword;

  using Elf_Rela   = typename ELF_T::Elf_Rela;
  using Elf_Rel    = typename ELF_T::Elf_Rel;

  VLOG(VDEBUG) << "[+] Building .plt.got relocations";

  it_pltgot_relocations pltgot_relocations = this->binary_->pltgot_relocations();

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
  auto&& it_pltgot_relocation = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_JMPREL;
      });

  auto&& it_pltgot_relocation_size = std::find_if(
      std::begin(this->binary_->dynamic_entries_),
      std::end(this->binary_->dynamic_entries_),
      [] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_PLTRELSZ;
      });

  if (it_pltgot_relocation == std::end(this->binary_->dynamic_entries_)) {
    throw LIEF::not_found("Unable to find the DT_JMPREL entry");
  }

  if (it_pltgot_relocation_size == std::end(this->binary_->dynamic_entries_)) {
    throw LIEF::not_found("Unable to find the DT_PLTRELSZ entry");
  }

  DynamicEntry* dt_reloc_addr = *it_pltgot_relocation;
  DynamicEntry* dt_reloc_size = *it_pltgot_relocation_size;

  Section& relocation_section = this->binary_->section_from_virtual_address((*it_pltgot_relocation)->value());
  if (isRela) {
    dt_reloc_size->value(pltgot_relocations.size() * sizeof(Elf_Rela));
  } else {
    dt_reloc_size->value(pltgot_relocations.size() * sizeof(Elf_Rel));
  }

  std::vector<uint8_t> content; // Section's content
  for (const Relocation& relocation : this->binary_->pltgot_relocations()) {


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


  if (content.size() > relocation_section.original_size()) {
    // Need relocation of the reloc section
    Segment relocation_load;
    relocation_load.type(SEGMENT_TYPES::PT_LOAD);
    relocation_load.flags(ELF_SEGMENT_FLAGS::PF_R | ELF_SEGMENT_FLAGS::PF_W);
    relocation_load.content(content);
    Segment& new_relocation_load = this->binary_->add(relocation_load);

    relocation_section.virtual_address(new_relocation_load.virtual_address());
    relocation_section.size(new_relocation_load.physical_size());
    relocation_section.offset(new_relocation_load.file_offset());
    relocation_section.content(new_relocation_load.content());

    relocation_section.original_size_ = new_relocation_load.physical_size();

    dt_reloc_addr->value(new_relocation_load.virtual_address());
    dt_reloc_size->value(content.size());

    return this->build<ELF_T>();
  }

  relocation_section.content(std::move(content));
}


template<typename ELF_T>
void Builder::build_symbol_requirement(void) {
  using Elf_Half    = typename ELF_T::Elf_Half;
  using Elf_Word    = typename ELF_T::Elf_Word;
  using Elf_Off     = typename ELF_T::Elf_Off;
  using Elf_Addr    = typename ELF_T::Elf_Addr;

  using Elf_Verneed = typename ELF_T::Elf_Verneed;
  using Elf_Vernaux = typename ELF_T::Elf_Vernaux;
  VLOG(VDEBUG) << "[+] Building symbol requirement";


  const Elf_Addr svr_address = this->binary_->get(DYNAMIC_TAGS::DT_VERNEED).value();
  const Elf_Off  svr_offset  = this->binary_->virtual_address_to_offset(svr_address);
  const uint32_t svr_nb     = static_cast<uint32_t>(this->binary_->get(DYNAMIC_TAGS::DT_VERNEEDNUM).value());

  if (svr_nb != this->binary_->symbol_version_requirements_.size()) {
    LOG(WARNING) << "The number of symbol version requirement \
      entries in the binary differ from the value in DT_VERNEEDNUM";
  }

  const Elf_Addr dyn_str_va = this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value();

  Section& dyn_str_section = this->binary_->section_from_virtual_address(dyn_str_va);
  std::vector<uint8_t> svr_raw;
  std::vector<uint8_t> dyn_str_raw = dyn_str_section.content();

  uint32_t svr_idx = 0;
  for (const SymbolVersionRequirement& svr: this->binary_->symbols_version_requirement()) {
    const std::string& name = svr.name();
    auto&& it_name_offset  = std::search(
        std::begin(dyn_str_raw),
        std::end(dyn_str_raw),
        name.c_str(),
        name.c_str() + name.size() + 1);

    Elf_Off name_offset = 0;

    if (it_name_offset != std::end(dyn_str_raw)) {
      name_offset = static_cast<uint64_t>(std::distance(std::begin(dyn_str_raw), it_name_offset));
    } else {
      VLOG(VDEBUG) << "[LIEF_DEBUG] buildSymbolRequirement(): Library name is not present";
      dyn_str_raw.insert(std::end(dyn_str_raw), std::begin(name), std::end(name));
      dyn_str_raw.push_back(0);
      name_offset = dyn_str_raw.size() - name.size() - 1;
    }

    it_const_symbols_version_aux_requirement svars = svr.auxiliary_symbols();

    Elf_Off next_symbol_offset = 0;
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

      Elf_Off svar_name_offset = 0;

      if (it_svar_name_offset != std::end(dyn_str_raw)) {
        svar_name_offset = static_cast<Elf_Off>(std::distance(std::begin(dyn_str_raw), it_svar_name_offset));
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
  if (dyn_str_raw.size() > dyn_str_section.original_size()) {
    LOG(INFO) << "Need to relocate the '" << dyn_str_section.name() << "' section";
    VLOG(VDEBUG) << std::dec << dyn_str_raw.size() <<  " > " << dyn_str_section.size();

    Segment dynstr;
    dynstr.type(SEGMENT_TYPES::PT_LOAD);
    dynstr.flags(ELF_SEGMENT_FLAGS::PF_R);
    dynstr.content(dyn_str_raw);

    Segment& new_segment = this->binary_->add(dynstr);

    dyn_str_section.virtual_address(new_segment.virtual_address());
    dyn_str_section.size(new_segment.physical_size());
    dyn_str_section.offset(new_segment.file_offset());
    dyn_str_section.content(new_segment.content());

    dyn_str_section.original_size_ = new_segment.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value(new_segment.virtual_address());
    this->binary_->get(DYNAMIC_TAGS::DT_STRSZ).value(dyn_str_raw.size());

    return this->build<ELF_T>();
  }

  this->binary_->section_from_offset(svr_offset).content(std::move(svr_raw));
  dyn_str_section.content(std::move(dyn_str_raw));

}

template<typename ELF_T>
void Builder::build_symbol_definition(void) {
  using Elf_Half    = typename ELF_T::Elf_Half;
  using Elf_Word    = typename ELF_T::Elf_Word;
  using Elf_Addr    = typename ELF_T::Elf_Addr;
  using Elf_Off     = typename ELF_T::Elf_Off;

  using Elf_Verdef  = typename ELF_T::Elf_Verdef;
  using Elf_Verdaux = typename ELF_T::Elf_Verdaux;

  VLOG(VDEBUG) << "[+] Building symbol definition";

  const Elf_Addr svd_va    = this->binary_->get(DYNAMIC_TAGS::DT_VERDEF).value();
  const Elf_Off svd_offset = this->binary_->virtual_address_to_offset(svd_va);
  const uint32_t svd_nb    = this->binary_->get(DYNAMIC_TAGS::DT_VERDEFNUM).value();

  if (svd_nb != this->binary_->symbol_version_definition_.size()) {
    LOG(WARNING) << "The number of symbol version definition entries\
      in the binary differ from the value in DT_VERDEFNUM";
  }


  const Elf_Addr dyn_str_va = this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value();
  Section& dyn_str_section = this->binary_->section_from_virtual_address(dyn_str_va);

  std::vector<uint8_t> svd_raw;
  std::vector<uint8_t> dyn_str_raw = dyn_str_section.content();

  uint32_t svd_idx = 0;
  for (const SymbolVersionDefinition& svd: this->binary_->symbols_version_definition()) {

    it_const_symbols_version_aux svas = svd.symbols_aux();

    Elf_Off next_symbol_offset = 0;

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

      Elf_Off sva_name_offset = 0;

      if (it_sva_name_offset != std::end(dyn_str_raw)) {
        sva_name_offset = static_cast<Elf_Off>(std::distance(std::begin(dyn_str_raw), it_sva_name_offset));
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

  if (dyn_str_raw.size() > dyn_str_section.original_size()) {
    LOG(INFO) << "Need to relocate the '" << dyn_str_section.name() << "' section";
    VLOG(VDEBUG) << std::dec << dyn_str_raw.size() <<  " > " << dyn_str_section.size();

    Segment dynstr;
    dynstr.type(SEGMENT_TYPES::PT_LOAD);
    dynstr.flags(ELF_SEGMENT_FLAGS::PF_R);
    dynstr.content(dyn_str_raw);

    Segment& new_segment = this->binary_->add(dynstr);

    dyn_str_section.virtual_address(new_segment.virtual_address());
    dyn_str_section.size(new_segment.physical_size());
    dyn_str_section.offset(new_segment.file_offset());
    dyn_str_section.content(new_segment.content());

    dyn_str_section.original_size_ = new_segment.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_STRTAB).value(new_segment.virtual_address());
    this->binary_->get(DYNAMIC_TAGS::DT_STRSZ).value(dyn_str_raw.size());

    return this->build<ELF_T>();
  }

  this->binary_->section_from_offset(svd_offset).content(std::move(svd_raw));
  dyn_str_section.content(std::move(dyn_str_raw));

}


template<typename ELF_T>
void Builder::relocate_dynamic_array(DynamicEntryArray& entry_array, DynamicEntry& entry_size) {
  using uint__     = typename ELF_T::uint;

  uint64_t original_init_size = entry_size.value();

  Section& array_section = this->binary_->section_from_virtual_address(entry_array.value());

  const std::vector<uint64_t>& array = entry_array.array();
  std::vector<uint8_t> array_content((array.size()) * sizeof(uint__), 0);
  VLOG(VDEBUG) << "Need to relocate the " << array_section.name() << " section";

  //uint64_t first_init_va = entry_array.value();

  // Create a segment:
  Segment array_segment;
  array_segment.type(SEGMENT_TYPES::PT_LOAD);
  array_segment += ELF_SEGMENT_FLAGS::PF_R;
  array_segment += ELF_SEGMENT_FLAGS::PF_W;
  array_segment.content(array_content);

  Segment& new_segment = this->binary_->add(array_segment);


  array_section.virtual_address(new_segment.virtual_address());
  array_section.size(new_segment.physical_size());
  array_section.offset(new_segment.file_offset());
  array_section.content(new_segment.content());
  array_section.original_size_ = new_segment.physical_size();


  // /!\ 'entry' is updated by  call 'add (segment)' /!
  uint64_t original_init_va = entry_array.value();
  VLOG(VDEBUG) << "Original Array address: " << std::hex << original_init_va << std::endl;
  if (this->binary_->header().file_type() == E_TYPE::ET_DYN) {
    for (Relocation& r : this->binary_->dynamic_relocations()) {

      // Check if the relocation address is within the .init_array
      if (original_init_va < (r.address() + 1) and (r.address() - 1) < (original_init_va + original_init_size)) {
        if (r.address() == (original_init_va + original_init_size)) {         // We are on the limit...
          if (entry_array[entry_array.size() - 1] == 0 and r.addend() == 0) { // And there is a 0-end
            continue;                                                         // Skip
          }
        }
        uint64_t new_address = array_section.virtual_address() + (r.address() - original_init_va);
        r.address(new_address);
      }

      if (original_init_va < (static_cast<uint64_t>(r.addend()) + 1) and (static_cast<uint64_t>(r.addend()) - 1) < (original_init_va + original_init_size)) {
        uint64_t new_addend = array_section.virtual_address() + (r.addend() - original_init_va);
        r.addend(new_addend);
      }
    }

    const ARCH arch = this->binary_->header().machine_type();

    for (size_t i = 0; i < array.size(); ++i) {
      Relocation* relocation = nullptr;
      uint64_t address_relocation = new_segment.virtual_address() + i * sizeof(uint__);
      auto&& it_relocation = std::find_if(
          std::begin(this->binary_->relocations_),
          std::end(this->binary_->relocations_),
          [&address_relocation] (const Relocation* r) {
            return r->address() == address_relocation;
          });


      // It's ok there is a relocation for the entry #i
      if (it_relocation != std::end(this->binary_->relocations_)) {
        continue;
      }

      // We are at the end of the array, there is not relocation
      // and the value is 0.
      // It should mean that 0 is the END
      if ((i == (array.size() - 1) and array[i] == 0)) {
        continue;
      }

      // We need to create a new RELATIVE relocation
      VLOG(VDEBUG) << "Can't find relocation for '0x" << std::hex << array[i]  << "' (0x" << address_relocation << ")" << std::endl;
      const bool is_rela = this->binary_->relocations_.back()->is_rela();

      switch (arch) {
        case ARCH::EM_ARM:
        {
          relocation = new Relocation(address_relocation, RELOC_ARM::R_ARM_RELATIVE, array[i], is_rela);
          break;
        }

        case ARCH::EM_AARCH64:
        {
          relocation = new Relocation(address_relocation, RELOC_AARCH64::R_AARCH64_RELATIVE, array[i], is_rela);
          break;
        }

        case ARCH::EM_386:
        {
          relocation = new Relocation(address_relocation, RELOC_i386::R_386_RELATIVE, array[i], is_rela);
          break;
        }

        case ARCH::EM_X86_64:
        {
          relocation = new Relocation(address_relocation, RELOC_x86_64::R_X86_64_RELATIVE, array[i], is_rela);
          break;
        }

        default:
        {
          LOG(WARNING) << to_string(arch) << " is not supported";
        }
      }

      if (relocation != nullptr) {
        relocation->purpose(RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC);
        relocation->architecture_ = arch;
        this->binary_->relocations_.push_back(relocation);
        VLOG(VDEBUG) << "Relocation added: " << *relocation << std::endl;
      }
    }
  }

  entry_array.value(new_segment.virtual_address());

}

template<typename ELF_T>
void Builder::build_interpreter(void) {
  VLOG(VDEBUG) << "[+] Building Interpreter" << std::endl;
  const std::string& inter_str = this->binary_->interpreter();

  // Look for the PT_INTERP segment
  auto&& it_pt_interp = std::find_if(
      std::begin(this->binary_->segments_),
      std::end(this->binary_->segments_),
      [] (const Segment* s) {
        return s->type() == SEGMENT_TYPES::PT_INTERP;
      });

  // Look for the ".interp" section
  auto&& it_section_interp = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* s) {
        return s->name() == ".interp";
      });


  if (it_pt_interp == std::end(this->binary_->segments_)) {
    throw not_found("Unable to find the INTERP segment");
  }

  Segment* interp_segment = *it_pt_interp;
  if (inter_str.size() > interp_segment->physical_size()) {
    LOG(INFO) << "The 'interpreter' segment needs to be relocated";

    // Create a LOAD segment for the new Interpreter:
    Segment load_interpreter_segment;
    load_interpreter_segment.type(SEGMENT_TYPES::PT_LOAD);
    load_interpreter_segment.flags(ELF_SEGMENT_FLAGS::PF_R);
    load_interpreter_segment.content({std::begin(inter_str), std::end(inter_str)});
    Segment& new_interpreter_load = this->binary_->add(load_interpreter_segment);

    interp_segment->virtual_address(new_interpreter_load.virtual_address());
    interp_segment->virtual_size(new_interpreter_load.virtual_size());
    interp_segment->physical_address(new_interpreter_load.physical_address());

    interp_segment->file_offset(new_interpreter_load.file_offset());
    interp_segment->physical_size(new_interpreter_load.physical_size());

    if (it_section_interp != std::end(this->binary_->sections_)) {
      Section* interp = *it_section_interp;
      interp->virtual_address(new_interpreter_load.virtual_address());
      interp->size(new_interpreter_load.physical_size());
      interp->offset(new_interpreter_load.file_offset());
      interp->content(new_interpreter_load.content());
      interp->original_size_ = new_interpreter_load.physical_size();
    }
    return this->build<ELF_T>();
  }
  const char* inter_cstr = inter_str.c_str();
  interp_segment->content({inter_cstr, inter_cstr + inter_str.size() + 1});
}

template<typename ELF_T>
void Builder::build_notes(void) {
  if (not this->binary_->has(SEGMENT_TYPES::PT_NOTE)) {
    return;
  }

  Segment& segment_note = this->binary_->get(SEGMENT_TYPES::PT_NOTE);
  std::vector<uint8_t> raw_notes;
  for (const Note& note : this->binary_->notes()) {
    // First we have to write the length of the Note's name
    const uint32_t namesz = static_cast<uint32_t>(note.name().size() + 1);
    raw_notes.insert(
        std::end(raw_notes),
        reinterpret_cast<const uint8_t*>(&namesz),
        reinterpret_cast<const uint8_t*>(&namesz) + sizeof(uint32_t));

    // Then the length of the Note's description
    const uint32_t descsz = static_cast<uint32_t>(note.description().size());
    //const uint32_t descsz = 20;
    raw_notes.insert(
        std::end(raw_notes),
        reinterpret_cast<const uint8_t*>(&descsz),
        reinterpret_cast<const uint8_t*>(&descsz) + sizeof(uint32_t));

    // Then the note's type
    const NOTE_TYPES type = note.type();
    raw_notes.insert(
        std::end(raw_notes),
        reinterpret_cast<const uint8_t*>(&type),
        reinterpret_cast<const uint8_t*>(&type) + sizeof(uint32_t));

    // Then we write the note's name
    const std::string& name = note.name();
    raw_notes.insert(
        std::end(raw_notes),
        reinterpret_cast<const uint8_t*>(name.c_str()),
        reinterpret_cast<const uint8_t*>(name.c_str()) + namesz);

    // Alignment
    raw_notes.resize(align(raw_notes.size(), sizeof(uint32_t)), 0);


    // description content
    const std::vector<uint8_t>& description = note.description();
    raw_notes.insert(
        std::end(raw_notes),
        std::begin(description),
        std::end(description));

    // Alignment
    raw_notes.resize(align(raw_notes.size(), sizeof(uint32_t)), 0);
  }

  if (segment_note.physical_size() < raw_notes.size()) {
    LOG(INFO) << "Segment Note needs to be relocated";
    Segment note = segment_note;
    note.virtual_address(0);
    note.file_offset(0);
    note.physical_address(0);
    note.physical_size(0);
    note.virtual_size(0);
    note.content(raw_notes);
    this->binary_->replace(note, segment_note);
    return this->build<ELF_T>();
  }

  segment_note.content(raw_notes);

  // ".note.ABI-tag" // NOTE_TYPES::NT_GNU_ABI_TAG
  // ===============
  //TODO: .note.netbds etc
  this->build(NOTE_TYPES::NT_GNU_ABI_TAG);
  this->build(NOTE_TYPES::NT_GNU_BUILD_ID);
  this->build(NOTE_TYPES::NT_GNU_GOLD_VERSION);


}

template<class ELF_T>
void Builder::build_symbol_version(void) {

  VLOG(VDEBUG) << "[+] Building symbol version" << std::endl;

  if (this->binary_->symbol_version_table_.size() != this->binary_->dynamic_symbols_.size()) {
    LOG(WARNING) << "The number of symbol version is different from the number of dynamic symbols ("
                 << std::dec << this->binary_->symbol_version_table_.size() << " != "
                 << this->binary_->dynamic_symbols_.size() << " ) " << std::endl;
  }

  const uint64_t sv_address = this->binary_->get(DYNAMIC_TAGS::DT_VERSYM).value();

  std::vector<uint8_t> sv_raw;
  sv_raw.reserve(this->binary_->symbol_version_table_.size() * sizeof(uint16_t));

  //for (const SymbolVersion* sv : this->binary_->symbol_version_table_) {
  for (const Symbol* symbol : this->binary_->dynamic_symbols_) {
    const SymbolVersion& sv = symbol->symbol_version();
    const uint16_t value = sv.value();
    sv_raw.insert(
        std::end(sv_raw),
        reinterpret_cast<const uint8_t*>(&value),
        reinterpret_cast<const uint8_t*>(&value) + sizeof(uint16_t));

  }

  Section& sv_section = this->binary_->section_from_virtual_address(sv_address);

  if (sv_raw.size() > sv_section.original_size()) {
    LOG(INFO) << "Need to relocate the '" << sv_section.name() << "' section";

    Segment sv_load;
    sv_load.type(SEGMENT_TYPES::PT_LOAD);
    sv_load.flags(ELF_SEGMENT_FLAGS::PF_R);
    sv_load.content(sv_raw);
    Segment& new_sv_load = this->binary_->add(sv_load);

    sv_section.virtual_address(new_sv_load.virtual_address());
    sv_section.size(new_sv_load.physical_size());
    sv_section.offset(new_sv_load.file_offset());
    sv_section.content(new_sv_load.content());

    sv_section.original_size_ = new_sv_load.physical_size();

    this->binary_->get(DYNAMIC_TAGS::DT_VERSYM).value(new_sv_load.virtual_address());
    return this->build<ELF_T>();
  }
  sv_section.content(std::move(sv_raw));


}




} // namespace ELF
} // namespace LIEF
