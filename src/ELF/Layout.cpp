#include "Layout.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Section.hpp"

#include <LIEF/iostream.hpp>
#include "Builder.tcc"

namespace LIEF {
namespace ELF {
Layout::Layout(Binary& bin) :
  binary_{&bin}
{}

Layout::~Layout() = default;

bool Layout::is_strtab_shared_shstrtab() const {
  // Check if the .strtab is shared with the .shstrtab
  const size_t shstrtab_idx = binary_->header().section_name_table_idx();
  size_t strtab_idx = 0;

  if (binary_->has(ELF_SECTION_TYPES::SHT_SYMTAB)) {
    const Section& symtab = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB);
    strtab_idx = symtab.link();
  } else {
    return false;
  }


  bool is_shared = true;
  const size_t nb_sections = binary_->sections().size();
  is_shared = is_shared and strtab_idx > 0 and shstrtab_idx > 0;
  is_shared = is_shared and strtab_idx < nb_sections and shstrtab_idx < nb_sections;
  is_shared = is_shared and strtab_idx == shstrtab_idx;
  return is_shared;
}

size_t Layout::section_strtab_size() {
  // could be moved in the class base.
  if (not raw_strtab_.empty()) {
    return raw_strtab_.size();
  }

  if (is_strtab_shared_shstrtab()) {
    // The content of .strtab is merged with .shstrtab
    return 0;
  }

  vector_iostream raw_strtab;
  raw_strtab.write<uint8_t>(0);

  size_t offset_counter = raw_strtab.tellp();

  if (binary_->static_symbols_.size() == 0) {
    return 0;
  }

  offset_counter = raw_strtab.tellp();
  std::vector<std::string> symstr_opt =
    Builder::optimize<Symbol, decltype(binary_->static_symbols_)>(binary_->static_symbols_,
                     [] (const Symbol* sym) { return sym->name(); },
                     offset_counter,
                     &strtab_name_map_);
  for (const std::string& name : symstr_opt) {
    raw_strtab.write(name);
  }
  raw_strtab.move(raw_strtab_);
  return raw_strtab_.size();
}

size_t Layout::section_shstr_size() {
  if (not raw_shstrtab_.empty()) {
    // Already in the cache
    return raw_shstrtab_.size();
  }

  vector_iostream raw_shstrtab;

  // In the ELF format all the .str sections
  // start with a null entry.
  raw_shstrtab.write<uint8_t>(0);

  // First write section names
  size_t offset_counter = raw_shstrtab.tellp();
  std::vector<std::string> shstrtab_opt =
    Builder::optimize<Section, decltype(binary_->sections_)>(binary_->sections_,
                      [] (const Section* sec) { return sec->name(); },
                      offset_counter,
                      &shstr_name_map_);

  for (const std::string& name : shstrtab_opt) {
    raw_shstrtab.write(name);
  }

  // Check if the .shstrtab and the .strtab are shared (optimization used by clang)
  // in this case, include the static symbol names
  if (binary_->static_symbols_.size() > 0 and is_strtab_shared_shstrtab()) {
    offset_counter = raw_shstrtab.tellp();
    std::vector<std::string> symstr_opt =
      Builder::optimize<Symbol, decltype(binary_->static_symbols_)>(binary_->static_symbols_,
                       [] (const Symbol* sym) { return sym->name(); },
                       offset_counter,
                       &shstr_name_map_);
    for (const std::string& name : symstr_opt) {
      raw_shstrtab.write(name);
    }
  }

  raw_shstrtab.move(raw_shstrtab_);
  return raw_shstrtab_.size();
}




}
}
