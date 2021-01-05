/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
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

#include "logging.hpp"

#include "LIEF/hash.hpp"

#include "LIEF/PE/json.hpp"
#include "LIEF/PE.hpp"

#include "Object.tcc"

namespace LIEF {
namespace PE {

std::string to_hex(const char c) {
  std::stringstream ss;
  ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)c);
  return std::string("\\x") + ss.str();
}

std::string escape_non_ascii(const std::string& s) {
  std::string result;
  const auto len = s.size();
  for (auto i = 0u; i < len; i++) {
    const auto c = s[i];
    if (c < 32 || c >= 127) {
      result += to_hex(c);
    } else {
      result.push_back(c);
    }
  }
  return result;
}

json to_json(const Object& v) {
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
}

std::string to_json_str(const Object& v) {
  return PE::to_json(v).dump();
}

void JsonVisitor::visit(const Binary& binary) {

  this->node_["name"]         = binary.name();
  this->node_["entrypoint"]   = binary.entrypoint();
  this->node_["virtual_size"] = binary.virtual_size();

  // DOS Header
  JsonVisitor dos_header_visitor;
  dos_header_visitor(binary.dos_header());

  // Rich Header
  if (binary.has_rich_header()) {
    JsonVisitor visitor;
    visitor(binary.rich_header());
    this->node_["rich_header"] = visitor.get();
  }

  // PE header
  JsonVisitor header_visitor;
  header_visitor(binary.header());

  // PE Optional Header
  JsonVisitor optional_header_visitor;
  optional_header_visitor(binary.optional_header());

  this->node_["dos_header"]      = dos_header_visitor.get();
  this->node_["header"]          = header_visitor.get();
  this->node_["optional_header"] = optional_header_visitor.get();

  // Data directories
  std::vector<json> data_directories;
  for (const DataDirectory& data_directory : binary.data_directories()) {
    JsonVisitor visitor;
    visitor(data_directory);
    data_directories.emplace_back(visitor.get());
  }
  this->node_["data_directories"] = data_directories;


  // Section
  std::vector<json> sections;
  for (const Section& section : binary.sections()) {
    JsonVisitor visitor;
    visitor(section);
    sections.emplace_back(visitor.get());
  }
  this->node_["sections"] = sections;

  // Relocations
  if (binary.has_relocations()) {
    std::vector<json> relocations;
    for (const Relocation& relocation : binary.relocations()) {
      JsonVisitor visitor;
      visitor(relocation);
      relocations.emplace_back(visitor.get());
    }
    this->node_["relocations"] = relocations;
  }

  // TLS
  if (binary.has_tls()) {
    JsonVisitor visitor;
    visitor(binary.tls());
    this->node_["tls"] = visitor.get();
  }


  // Exports
  if (binary.has_exports()) {
    JsonVisitor visitor;
    visitor(binary.get_export());
    this->node_["export"] = visitor.get();
  }


  // Debug
  if (binary.has_debug()) {
    std::vector<json> debug_entries;
    for (const Debug& debug : binary.debug()) {
      JsonVisitor visitor;
      visitor(debug);
      debug_entries.emplace_back(visitor.get());
    }
    this->node_["debug"] = debug_entries;
  }

  // Imports
  if (binary.has_imports()) {
    std::vector<json> imports;
    for (const Import& import : binary.imports()) {
      JsonVisitor visitor;
      visitor(import);
      imports.emplace_back(visitor.get());
    }
    this->node_["imports"] = imports;
  }

  // Resources
  if (binary.has_resources()) {
    JsonVisitor visitor;
    binary.resources().accept(visitor);

    JsonVisitor manager_visitor;
    binary.resources_manager().accept(manager_visitor);

    this->node_["resources_tree"]    = visitor.get();
    this->node_["resources_manager"] = manager_visitor.get();
  }


  // Signatures
  std::vector<json> sigs;
  if (binary.has_signatures()) {
    for (const Signature& sig : binary.signatures()) {
      JsonVisitor visitor;
      visitor(sig);
      sigs.push_back(std::move(visitor.get()));
    }
    this->node_["signatures"] = sigs;
  }

  std::vector<json> symbols;
  for (const Symbol& symbol : binary.symbols()) {
    JsonVisitor visitor;
    visitor(symbol);
    symbols.emplace_back(visitor.get());
  }
  if (!symbols.empty()) {
    this->node_["symbols"] = symbols;
  }

  // Load Configuration
  if (binary.has_configuration()) {
    JsonVisitor visitor;
    const LoadConfiguration& config = binary.load_configuration();
    config.accept(visitor);
    this->node_["load_configuration"] = visitor.get();
  }

}


void JsonVisitor::visit(const DosHeader& dos_header) {

  this->node_["magic"]                       = dos_header.magic();
  this->node_["used_bytes_in_the_last_page"] = dos_header.used_bytes_in_the_last_page();
  this->node_["file_size_in_pages"]          = dos_header.file_size_in_pages();
  this->node_["numberof_relocation"]         = dos_header.numberof_relocation();
  this->node_["header_size_in_paragraphs"]   = dos_header.header_size_in_paragraphs();
  this->node_["minimum_extra_paragraphs"]    = dos_header.minimum_extra_paragraphs();
  this->node_["maximum_extra_paragraphs"]    = dos_header.maximum_extra_paragraphs();
  this->node_["initial_relative_ss"]         = dos_header.initial_relative_ss();
  this->node_["initial_sp"]                  = dos_header.initial_sp();
  this->node_["checksum"]                    = dos_header.checksum();
  this->node_["initial_ip"]                  = dos_header.initial_ip();
  this->node_["initial_relative_cs"]         = dos_header.initial_relative_cs();
  this->node_["addressof_relocation_table"]  = dos_header.addressof_relocation_table();
  this->node_["overlay_number"]              = dos_header.overlay_number();
  this->node_["reserved"]                    = dos_header.reserved();
  this->node_["oem_id"]                      = dos_header.oem_id();
  this->node_["oem_info"]                    = dos_header.oem_info();
  this->node_["reserved2"]                   = dos_header.reserved2();
  this->node_["addressof_new_exeheader"]     = dos_header.addressof_new_exeheader();
}

void JsonVisitor::visit(const RichHeader& rich_header) {
  std::vector<json> entries;
  for (const RichEntry& entry : rich_header.entries()) {
    JsonVisitor visitor;
    visitor(entry);
    entries.emplace_back(visitor.get());
  }

  this->node_["key"]     = rich_header.key();
  this->node_["entries"] = entries;
}

void JsonVisitor::visit(const RichEntry& rich_entry) {
  this->node_["id"]       = rich_entry.id();
  this->node_["build_id"] = rich_entry.build_id();
  this->node_["count"]    = rich_entry.count();
}

void JsonVisitor::visit(const Header& header) {
  this->node_["signature"]              = header.signature();
  this->node_["machine"]                = to_string(header.machine());
  this->node_["numberof_sections"]      = header.numberof_sections();
  this->node_["time_date_stamp"]        = header.time_date_stamp();
  this->node_["pointerto_symbol_table"] = header.pointerto_symbol_table();
  this->node_["numberof_symbols"]       = header.numberof_symbols();
  this->node_["sizeof_optional_header"] = header.sizeof_optional_header();
  this->node_["characteristics"]        = static_cast<size_t>(header.characteristics());
}

void JsonVisitor::visit(const OptionalHeader& optional_header) {
  this->node_["magic"]                          = to_string(optional_header.magic());
  this->node_["major_linker_version"]           = optional_header.major_linker_version();
  this->node_["minor_linker_version"]           = optional_header.minor_linker_version();
  this->node_["sizeof_code"]                    = optional_header.sizeof_code();
  this->node_["sizeof_initialized_data"]        = optional_header.sizeof_initialized_data();
  this->node_["sizeof_uninitialized_data"]      = optional_header.sizeof_uninitialized_data();
  this->node_["addressof_entrypoint"]           = optional_header.addressof_entrypoint();
  this->node_["baseof_code"]                    = optional_header.baseof_code();
  if (optional_header.magic() == PE_TYPE::PE32) {
    this->node_["baseof_data"]     = optional_header.baseof_data();
  }
  this->node_["imagebase"]                      = optional_header.imagebase();
  this->node_["section_alignment"]              = optional_header.section_alignment();
  this->node_["file_alignment"]                 = optional_header.file_alignment();
  this->node_["major_operating_system_version"] = optional_header.major_operating_system_version();
  this->node_["minor_operating_system_version"] = optional_header.minor_operating_system_version();
  this->node_["major_image_version"]            = optional_header.major_image_version();
  this->node_["minor_image_version"]            = optional_header.minor_image_version();
  this->node_["major_subsystem_version"]        = optional_header.major_subsystem_version();
  this->node_["minor_subsystem_version"]        = optional_header.minor_subsystem_version();
  this->node_["win32_version_value"]            = optional_header.win32_version_value();
  this->node_["sizeof_image"]                   = optional_header.sizeof_image();
  this->node_["sizeof_headers"]                 = optional_header.sizeof_headers();
  this->node_["checksum"]                       = optional_header.checksum();
  this->node_["subsystem"]                      = to_string(optional_header.subsystem());
  this->node_["dll_characteristics"]            = optional_header.dll_characteristics();
  this->node_["sizeof_stack_reserve"]           = optional_header.sizeof_stack_reserve();
  this->node_["sizeof_stack_commit"]            = optional_header.sizeof_stack_commit();
  this->node_["sizeof_heap_reserve"]            = optional_header.sizeof_heap_reserve();
  this->node_["sizeof_heap_commit"]             = optional_header.sizeof_heap_commit();
  this->node_["loader_flags"]                   = optional_header.loader_flags();
  this->node_["numberof_rva_and_size"]          = optional_header.numberof_rva_and_size();
}

void JsonVisitor::visit(const DataDirectory& data_directory) {
  this->node_["RVA"]  = data_directory.RVA();
  this->node_["size"] = data_directory.size();
  this->node_["type"] = to_string(data_directory.type());
  if (data_directory.has_section()) {
    this->node_["section"] = escape_non_ascii(data_directory.section().name());
  }
}

void JsonVisitor::visit(const Section& section) {

  std::vector<json> characteristics;
  for (SECTION_CHARACTERISTICS c : section.characteristics_list()) {
    characteristics.emplace_back(to_string(c));
  }

  std::vector<json> types;
  for (PE_SECTION_TYPES t : section.types()) {
    types.emplace_back(to_string(t));
  }

  this->node_["name"]                   = escape_non_ascii(section.name());
  this->node_["pointerto_relocation"]   = section.pointerto_relocation();
  this->node_["pointerto_line_numbers"] = section.pointerto_line_numbers();
  this->node_["numberof_relocations"]   = section.numberof_relocations();
  this->node_["numberof_line_numbers"]  = section.numberof_line_numbers();
  this->node_["entropy"]                = section.entropy();
  this->node_["characteristics"]        = characteristics;
  this->node_["types"]                  = types;
}

void JsonVisitor::visit(const Relocation& relocation) {
  std::vector<json> entries;
  for (const RelocationEntry& entry : relocation.entries()) {
    JsonVisitor visitor;
    visitor(entry);
    entries.emplace_back(visitor.get());
  }

  this->node_["virtual_address"] = relocation.virtual_address();
  this->node_["block_size"]      = relocation.block_size();
  this->node_["entries"]         = entries;
}

void JsonVisitor::visit(const RelocationEntry& relocation_entry) {
  this->node_["data"]     = relocation_entry.data();
  this->node_["position"] = relocation_entry.position();
  this->node_["type"]     = to_string(relocation_entry.type());
}

void JsonVisitor::visit(const Export& export_) {

  std::vector<json> entries;
  for (const ExportEntry& entry : export_.entries()) {
    JsonVisitor visitor;
    visitor(entry);
    entries.emplace_back(visitor.get());
  }
  this->node_["export_flags"]  = export_.export_flags();
  this->node_["timestamp"]     = export_.timestamp();
  this->node_["major_version"] = export_.major_version();
  this->node_["minor_version"] = export_.minor_version();
  this->node_["ordinal_base"]  = export_.ordinal_base();
  this->node_["name"]          = escape_non_ascii(export_.name());
  this->node_["entries"]       = entries;
}

void JsonVisitor::visit(const ExportEntry& export_entry) {
  this->node_["name"]      = escape_non_ascii(export_entry.name());
  this->node_["ordinal"]   = export_entry.ordinal();
  this->node_["address"]   = export_entry.address();
  this->node_["is_extern"] = export_entry.is_extern();

  if (export_entry.is_forwarded()) {
    const ExportEntry::forward_information_t& fwd_info = export_entry.forward_information();
    this->node_["forward_information"] = {
      {"library",  fwd_info.library},
      {"function", fwd_info.function},
    };
  }
}

void JsonVisitor::visit(const TLS& tls) {

  this->node_["callbacks"]           = tls.callbacks();
  this->node_["addressof_raw_data"]  = std::vector<uint64_t>{tls.addressof_raw_data().first, tls.addressof_raw_data().second};
  this->node_["addressof_index"]     = tls.addressof_index();
  this->node_["addressof_callbacks"] = tls.addressof_callbacks();
  this->node_["sizeof_zero_fill"]    = tls.sizeof_zero_fill();
  this->node_["characteristics"]     = tls.characteristics();

  if (tls.has_data_directory()) {
    this->node_["data_directory"] = to_string(tls.directory().type());
  }

  if (tls.has_section()) {
    this->node_["section"] = escape_non_ascii(tls.section().name());
  }
}

void JsonVisitor::visit(const Symbol& symbol) {

  this->node_["value"]                = symbol.value();
  this->node_["size"]                 = symbol.size();
  this->node_["name"]                 = symbol.name();

  this->node_["section_number"]       = symbol.section_number();
  this->node_["type"]                 = symbol.type();
  this->node_["base_type"]            = to_string(symbol.base_type());
  this->node_["complex_type"]         = to_string(symbol.complex_type());
  this->node_["storage_class"]        = to_string(symbol.storage_class());
  this->node_["numberof_aux_symbols"] = symbol.numberof_aux_symbols();

  if (symbol.has_section()) {
    this->node_["section"] = symbol.section().name();
  }
}

void JsonVisitor::visit(const Debug& debug) {
  this->node_["characteristics"]   = debug.characteristics();
  this->node_["timestamp"]         = debug.timestamp();
  this->node_["major_version"]     = debug.major_version();
  this->node_["minor_version"]     = debug.minor_version();
  this->node_["type"]              = to_string(debug.type());
  this->node_["sizeof_data"]       = debug.sizeof_data();
  this->node_["addressof_rawdata"] = debug.addressof_rawdata();
  this->node_["pointerto_rawdata"] = debug.pointerto_rawdata();

  if (debug.has_code_view()) {
    JsonVisitor codeview_visitor;
    const CodeView& codeview = debug.code_view();
    codeview.accept(codeview_visitor);
    this->node_["code_view"] = codeview_visitor.get();
  }

  if (debug.has_pogo()) {
    JsonVisitor pogo_visitor;
    const Pogo& pogo = debug.pogo();
    pogo.accept(pogo_visitor);
    this->node_["pogo"] = pogo_visitor.get();
  }
}

void JsonVisitor::visit(const CodeView& cv) {
  this->node_["cv_signature"] = to_string(cv.cv_signature());
}

void JsonVisitor::visit(const CodeViewPDB& cvpdb) {
  this->visit(static_cast<const CodeView&>(cvpdb));
  this->node_["signature"] = cvpdb.signature();
  this->node_["age"]       = cvpdb.age();
  this->node_["filename"]  = escape_non_ascii(cvpdb.filename());
}

void JsonVisitor::visit(const Import& import) {

  std::vector<json> entries;
  for (const ImportEntry& entry : import.entries()) {
    JsonVisitor visitor;
    visitor(entry);
    entries.emplace_back(visitor.get());
  }

  this->node_["forwarder_chain"]          = import.forwarder_chain();
  this->node_["timedatestamp"]            = import.timedatestamp();
  this->node_["import_address_table_rva"] = import.import_address_table_rva();
  this->node_["import_lookup_table_rva"]  = import.import_lookup_table_rva();
  this->node_["name"]                     = import.name();
  this->node_["entries"]                  = entries;

}

void JsonVisitor::visit(const ImportEntry& import_entry) {
  if (import_entry.is_ordinal()) {
    this->node_["ordinal"] = import_entry.ordinal();
  } else {
    this->node_["name"] = import_entry.name();
  }

  this->node_["iat_address"] = import_entry.iat_address();
  this->node_["data"]        = import_entry.data();
  this->node_["hint"]        = import_entry.hint();
}

void JsonVisitor::visit(const ResourceData& resource_data) {
  this->node_["code_page"] = resource_data.code_page();
  this->node_["reserved"]  = resource_data.reserved();
  this->node_["offset"]    = resource_data.offset();
  this->node_["hash"]      = Hash::hash(resource_data.content());

}

void JsonVisitor::visit(const ResourceNode& resource_node) {
  this->node_["id"] = resource_node.id();

  if (resource_node.has_name()) {
    this->node_["name"] = u16tou8(resource_node.name());
  }

  if (resource_node.childs().size() > 0) {
    std::vector<json> childs;
    for (const ResourceNode& rsrc : resource_node.childs()) {
      JsonVisitor visitor;
      rsrc.accept(visitor);
      childs.emplace_back(visitor.get());
    }

    this->node_["childs"] = childs;
  }

}

void JsonVisitor::visit(const ResourceDirectory& resource_directory) {
  this->node_["id"] = resource_directory.id();

  if (resource_directory.has_name()) {
    this->node_["name"] = u16tou8(resource_directory.name());
  }

  this->node_["characteristics"]       = resource_directory.characteristics();
  this->node_["time_date_stamp"]       = resource_directory.time_date_stamp();
  this->node_["major_version"]         = resource_directory.major_version();
  this->node_["minor_version"]         = resource_directory.minor_version();
  this->node_["numberof_name_entries"] = resource_directory.numberof_name_entries();
  this->node_["numberof_id_entries"]   = resource_directory.numberof_id_entries();

  if (resource_directory.childs().size() > 0) {
    std::vector<json> childs;
    for (const ResourceNode& rsrc : resource_directory.childs()) {
      JsonVisitor visitor;
      rsrc.accept(visitor);
      childs.emplace_back(visitor.get());
    }

    this->node_["childs"] = childs;
  }
}


void JsonVisitor::visit(const ResourcesManager& resources_manager) {
  if (resources_manager.has_manifest()) {
    try {
      this->node_["manifest"] = escape_non_ascii(resources_manager.manifest()) ;
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (resources_manager.has_html()) {
    try {
      this->node_["html"] = resources_manager.html();
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (resources_manager.has_version()) {
    JsonVisitor version_visitor;
    try {
      version_visitor(resources_manager.version());
      this->node_["version"] = version_visitor.get();
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (resources_manager.has_icons()) {
    std::vector<json> icons;
    try {
      for (const ResourceIcon& icon : resources_manager.icons()) {
        JsonVisitor icon_visitor;
        icon_visitor(icon);
        icons.emplace_back(icon_visitor.get());
      }
      this->node_["icons"] = icons;
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (resources_manager.has_dialogs()) {
    std::vector<json> dialogs;
    try {
      for (const ResourceDialog& dialog : resources_manager.dialogs()) {
        JsonVisitor dialog_visitor;
        dialog_visitor(dialog);
        dialogs.emplace_back(dialog_visitor.get());
      }
      this->node_["dialogs"] = dialogs;
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (resources_manager.has_string_table()) {
    std::vector<json> string_table_json;
    try {
      for (const ResourceStringTable& string_table : resources_manager.string_table()) {
        JsonVisitor string_table_visitor;
        string_table_visitor(string_table);
        string_table_json.emplace_back(string_table_visitor.get());
        this->node_["string_table"] = string_table_json;
      }
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (resources_manager.has_accelerator()) {
    std::vector<json> accelerator_json;
    try {
      for (const ResourceAccelerator& acc : resources_manager.accelerator()) {
        JsonVisitor accelerator_visitor;
        accelerator_visitor(acc);
        accelerator_json.emplace_back(accelerator_visitor.get());
        this->node_["accelerator"] = accelerator_json;
      }
    } catch (const LIEF::exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }
}

void JsonVisitor::visit(const ResourceStringFileInfo& resource_sfi) {

  std::vector<json> langcode_items;
  for (const LangCodeItem& item : resource_sfi.langcode_items()) {
    JsonVisitor langcode_visitor;
    langcode_visitor(item);
    langcode_items.emplace_back(langcode_visitor.get());
  }

  this->node_["type"]  = resource_sfi.type();
  this->node_["key"]   = u16tou8(resource_sfi.key());
  this->node_["langcode_items"] = langcode_items;
}

void JsonVisitor::visit(const ResourceFixedFileInfo& resource_ffi) {
  this->node_["signature"]          = resource_ffi.signature();
  this->node_["struct_version"]     = resource_ffi.struct_version();
  this->node_["file_version_MS"]    = resource_ffi.file_version_MS();
  this->node_["file_version_LS"]    = resource_ffi.file_version_LS();
  this->node_["product_version_MS"] = resource_ffi.product_version_MS();
  this->node_["product_version_LS"] = resource_ffi.product_version_LS();
  this->node_["file_flags_mask"]    = resource_ffi.file_flags_mask();
  this->node_["file_flags"]         = resource_ffi.file_flags();
  this->node_["file_os"]            = to_string(resource_ffi.file_os());
  this->node_["file_type"]          = to_string(resource_ffi.file_type());
  this->node_["file_subtype"]       = to_string(resource_ffi.file_subtype());
  this->node_["file_date_MS"]       = resource_ffi.file_date_MS();
  this->node_["file_date_LS"]       = resource_ffi.file_date_LS();
}

void JsonVisitor::visit(const ResourceVarFileInfo& resource_vfi) {
  this->node_["type"]         = resource_vfi.type();
  this->node_["key"]          = u16tou8(resource_vfi.key());
  this->node_["translations"] = resource_vfi.translations();
}

void JsonVisitor::visit(const LangCodeItem& resource_lci) {
  std::map<std::string, std::string> items;
  std::transform(
      std::begin(resource_lci.items()),
      std::end(resource_lci.items()),
      std::insert_iterator<decltype(items)>(items, std::end(items)),
      [] (const std::pair<std::u16string, std::u16string>& p) {
        return std::pair<std::string, std::string>{u16tou8(p.first), u16tou8(p.second)};
      });

  this->node_["type"]  = resource_lci.type();
  this->node_["key"]   = u16tou8(resource_lci.key());
  this->node_["items"] = items;

}


void JsonVisitor::visit(const ResourceVersion& resource_version) {
  this->node_["type"] = resource_version.type();
  this->node_["key"]  = u16tou8(resource_version.key());

  if (resource_version.has_fixed_file_info()) {
    JsonVisitor visitor;
    visitor(resource_version.fixed_file_info());
    this->node_["fixed_file_info"] = visitor.get();
  }


  if (resource_version.has_string_file_info()) {
    JsonVisitor visitor;
    visitor(resource_version.string_file_info());
    this->node_["string_file_info"] = visitor.get();
  }


  if (resource_version.has_var_file_info()) {
    JsonVisitor visitor;
    visitor(resource_version.var_file_info());
    this->node_["var_file_info"] = visitor.get();
  }
}

void JsonVisitor::visit(const ResourceIcon& resource_icon) {
  this->node_["id"]          = resource_icon.id();
  this->node_["lang"]        = to_string(resource_icon.lang());
  this->node_["sublang"]     = to_string(resource_icon.sublang());
  this->node_["width"]       = resource_icon.width();
  this->node_["height"]      = resource_icon.height();
  this->node_["color_count"] = resource_icon.color_count();
  this->node_["reserved"]    = resource_icon.reserved();
  this->node_["planes"]      = resource_icon.planes();
  this->node_["bit_count"]   = resource_icon.bit_count();
  this->node_["pixels"]      = Hash::hash(resource_icon.pixels());
}

void JsonVisitor::visit(const ResourceDialog& dialog) {
  this->node_["x"]              = dialog.x();
  this->node_["y"]              = dialog.y();
  this->node_["cx"]             = dialog.cx();
  this->node_["cy"]             = dialog.cy();
  this->node_["style"]          = dialog.style();
  this->node_["extended_style"] = dialog.extended_style();

  std::vector<json> dialog_items;
  for (const ResourceDialogItem& item : dialog.items()) {
    JsonVisitor dialogitem_visitor;
    dialogitem_visitor(item);
    dialog_items.emplace_back(dialogitem_visitor.get());
  }

  this->node_["items"] = dialog_items;

  if (dialog.is_extended()) {
    this->node_["version"]    = dialog.version();
    this->node_["signature"]  = dialog.signature();
    this->node_["help_id"]    = dialog.help_id();
    this->node_["weight"]     = dialog.weight();
    this->node_["point_size"] = dialog.point_size();
    this->node_["is_italic"]  = dialog.is_italic();
    this->node_["charset"]    = dialog.charset();
    this->node_["title"]      = u16tou8(dialog.title());
    this->node_["typeface"]   = u16tou8(dialog.typeface());
  }
}


void JsonVisitor::visit(const ResourceDialogItem& dialog_item) {
  this->node_["id"]             = dialog_item.id();
  this->node_["x"]              = dialog_item.x();
  this->node_["y"]              = dialog_item.y();
  this->node_["cx"]             = dialog_item.cx();
  this->node_["cy"]             = dialog_item.cy();
  this->node_["style"]          = dialog_item.style();
  this->node_["extended_style"] = dialog_item.extended_style();

  if (dialog_item.is_extended()) {
    this->node_["title"]   = u16tou8(dialog_item.title());
    this->node_["help_id"] = dialog_item.help_id();
  }

}

void JsonVisitor::visit(const ResourceStringTable& string_table) {
  this->node_["length"] = string_table.length();
  this->node_["name"] = u16tou8(string_table.name());
}

void JsonVisitor::visit(const ResourceAccelerator& acc) {
  std::vector<json> flags;
  for (const ACCELERATOR_FLAGS c : acc.flags_list()) {
    flags.emplace_back(to_string(c));
  }
  this->node_["flags"]   = flags;
  this->node_["ansi"]    = acc.ansi_str();
  this->node_["id"]      = acc.id();
  this->node_["padding"] = acc.padding();
}

void JsonVisitor::visit(const Signature& signature) {

  JsonVisitor content_info_visitor;
  content_info_visitor(signature.content_info());

  std::vector<json> jsigners;
  for (const SignerInfo& signer : signature.signers()) {
    JsonVisitor visitor;
    visitor(signer);
    jsigners.emplace_back(std::move(visitor.get()));
  }

  std::vector<json> crts;
  for (const x509& crt : signature.certificates()) {
    JsonVisitor crt_visitor;
    crt_visitor(crt);
    crts.emplace_back(std::move(crt_visitor.get()));
  }

  this->node_["digest_algorithm"] = to_string(signature.digest_algorithm());
  this->node_["version"]          = signature.version();
  this->node_["content_info"]     = content_info_visitor.get();
  this->node_["signer_info"]      = jsigners;
  this->node_["certificates"]     = crts;
}

void JsonVisitor::visit(const x509& x509) {
  this->node_["serial_number"]       = x509.serial_number();
  this->node_["version"]             = x509.version();
  this->node_["issuer"]              = x509.issuer();
  this->node_["subject"]             = x509.subject();
  this->node_["signature_algorithm"] = x509.signature_algorithm();
  this->node_["valid_from"]          = x509.valid_from();
  this->node_["valid_to"]            = x509.valid_to();
}

void JsonVisitor::visit(const SignerInfo& signerinfo) {
  std::vector<json> auth_attrs;
  for (const Attribute& attr : signerinfo.authenticated_attributes()) {
    JsonVisitor visitor;
    visitor(attr);
    auth_attrs.emplace_back(std::move(visitor.get()));
  }

  std::vector<json> unauth_attrs;
  for (const Attribute& attr : signerinfo.unauthenticated_attributes()) {
    JsonVisitor visitor;
    visitor(attr);
    auth_attrs.emplace_back(std::move(visitor.get()));
  }

  this->node_["version"]                    = signerinfo.version();
  this->node_["digest_algorithm"]           = to_string(signerinfo.digest_algorithm());
  this->node_["encryption_algorithm"]       = to_string(signerinfo.encryption_algorithm());
  this->node_["encrypted_digest"]           = signerinfo.encrypted_digest();
  this->node_["issuer"]                     = signerinfo.issuer();
  this->node_["serial_number"]              = signerinfo.serial_number();
  this->node_["authenticated_attributes"]   = auth_attrs;
  this->node_["unauthenticated_attributes"] = unauth_attrs;
}

void JsonVisitor::visit(const ContentInfo& contentinfo) {
  this->node_["content_type"]     = contentinfo.content_type();
  this->node_["digest_algorithm"] = to_string(contentinfo.digest_algorithm());
  this->node_["digest"]           = contentinfo.digest();
  this->node_["file"]             = contentinfo.file();
}

void JsonVisitor::visit(const Attribute& auth) {
  this->node_["type"] = to_string(auth.type());
}

void JsonVisitor::visit(const ContentType& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["oid"] = attr.oid();
}

void JsonVisitor::visit(const GenericType& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["oid"] = attr.oid();
}

void JsonVisitor::visit(const MsSpcNestedSignature& attr) {
  this->visit(*attr.as<Attribute>());
  JsonVisitor visitor;
  visitor(attr.sig());
  this->node_["signature"] = std::move(visitor.get());
}

void JsonVisitor::visit(const MsSpcStatementType& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["oid"] = attr.oid();
}

void JsonVisitor::visit(const PKCS9AtSequenceNumber& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["number"] = attr.number();
}
void JsonVisitor::visit(const PKCS9CounterSignature& attr) {
  this->visit(*attr.as<Attribute>());

  std::vector<json> signers;
  for (const SignerInfo& signer : attr.signers()) {
    JsonVisitor visitor;
    visitor(signer);
    signers.emplace_back(std::move(visitor.get()));
  }
  this->node_["signers"] = std::move(signers);
}

void JsonVisitor::visit(const PKCS9MessageDigest& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["digest"] = attr.digest();
}

void JsonVisitor::visit(const PKCS9SigningTime& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["time"] = attr.time();
}

void JsonVisitor::visit(const SpcSpOpusInfo& attr) {
  this->visit(*attr.as<Attribute>());
  this->node_["more_info"]    = attr.more_info();
  this->node_["program_name"] = attr.program_name();
}

void JsonVisitor::visit(const CodeIntegrity& code_integrity) {
  this->node_["flags"]          = code_integrity.flags();
  this->node_["catalog"]        = code_integrity.catalog();
  this->node_["catalog_offset"] = code_integrity.catalog_offset();
  this->node_["reserved"]       = code_integrity.reserved();
}

void JsonVisitor::visit(const LoadConfiguration& config) {
  this->node_["version"]                          = to_string(config.version());
  this->node_["characteristics"]                  = config.characteristics();
  this->node_["timedatestamp"]                    = config.timedatestamp();
  this->node_["major_version"]                    = config.major_version();
  this->node_["minor_version"]                    = config.minor_version();
  this->node_["global_flags_clear"]               = config.global_flags_clear();
  this->node_["global_flags_set"]                 = config.global_flags_set();
  this->node_["critical_section_default_timeout"] = config.critical_section_default_timeout();
  this->node_["decommit_free_block_threshold"]    = config.decommit_free_block_threshold();
  this->node_["decommit_total_free_threshold"]    = config.decommit_total_free_threshold();
  this->node_["lock_prefix_table"]                = config.lock_prefix_table();
  this->node_["maximum_allocation_size"]          = config.maximum_allocation_size();
  this->node_["virtual_memory_threshold"]         = config.virtual_memory_threshold();
  this->node_["process_affinity_mask"]            = config.process_affinity_mask();
  this->node_["process_heap_flags"]               = config.process_heap_flags();
  this->node_["csd_version"]                      = config.csd_version();
  this->node_["reserved1"]                        = config.reserved1();
  this->node_["editlist"]                         = config.editlist();
  this->node_["security_cookie"]                  = config.security_cookie();

}

void JsonVisitor::visit(const LoadConfigurationV0& config) {
  this->node_["se_handler_table"] = config.se_handler_table();
  this->node_["se_handler_count"] = config.se_handler_count();
  this->visit(static_cast<const LoadConfiguration&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV1& config) {
  this->node_["guard_cf_check_function_pointer"]    = config.guard_cf_check_function_pointer();
  this->node_["guard_cf_dispatch_function_pointer"] = config.guard_cf_dispatch_function_pointer();
  this->node_["guard_cf_function_table"]            = config.guard_cf_function_table();
  this->node_["guard_cf_function_count"]            = config.guard_cf_function_count();
  this->node_["guard_flags"]                        = static_cast<size_t>(config.guard_flags());
  this->visit(static_cast<const LoadConfigurationV0&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV2& config) {
  JsonVisitor code_integrity_visitor;
  code_integrity_visitor(config.code_integrity());

  this->node_["code_integrity"] = code_integrity_visitor.get();
  this->visit(static_cast<const LoadConfigurationV1&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV3& config) {
  this->node_["guard_address_taken_iat_entry_table"] = config.guard_address_taken_iat_entry_table();
  this->node_["guard_address_taken_iat_entry_count"] = config.guard_address_taken_iat_entry_count();
  this->node_["guard_long_jump_target_table"]        = config.guard_long_jump_target_table();
  this->node_["guard_long_jump_target_count"]        = config.guard_long_jump_target_count();
  this->visit(static_cast<const LoadConfigurationV2&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV4& config) {
  this->node_["dynamic_value_reloc_table"] = config.dynamic_value_reloc_table();
  this->node_["hybrid_metadata_pointer"]   = config.hybrid_metadata_pointer();
  this->visit(static_cast<const LoadConfigurationV3&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV5& config) {
  this->node_["guard_rf_failure_routine"]                   = config.guard_rf_failure_routine();
  this->node_["guard_rf_failure_routine_function_pointer"]  = config.guard_rf_failure_routine_function_pointer();
  this->node_["dynamic_value_reloctable_offset"]            = config.dynamic_value_reloctable_offset();
  this->node_["dynamic_value_reloctable_section"]           = config.dynamic_value_reloctable_section();
  this->node_["reserved2"]                                  = config.guard_rf_failure_routine();
  this->visit(static_cast<const LoadConfigurationV4&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV6& config) {
  this->node_["guard_rf_verify_stackpointer_function_pointer"]  = config.guard_rf_verify_stackpointer_function_pointer();
  this->node_["hotpatch_table_offset"]                          = config.hotpatch_table_offset();
  this->visit(static_cast<const LoadConfigurationV5&>(config));
}

void JsonVisitor::visit(const LoadConfigurationV7& config) {
  this->node_["reserved3"]                = config.reserved3();
  this->node_["addressof_unicode_string"] = config.addressof_unicode_string();
  this->visit(static_cast<const LoadConfigurationV6&>(config));
}


void JsonVisitor::visit(const Pogo& pogo) {
  this->node_["signature"] = to_string(pogo.signature());

  std::vector<json> entries;
  for (const PogoEntry& entry : pogo.entries()) {
    JsonVisitor v;
    v(entry);
    entries.emplace_back(v.get());
  }
  this->node_["entries"] = entries;
}

void JsonVisitor::visit(const PogoEntry& entry) {
  this->node_["name"]      = entry.name();
  this->node_["start_rva"] = entry.start_rva();
  this->node_["size"]      = entry.size();
}


// LIEF Abstract
void JsonVisitor::visit(const LIEF::Binary& binary) {
  // It should be a ELF::Binary so we don't catch "std::bad_cast"
  this->visit(*dynamic_cast<const LIEF::PE::Binary*>(&binary));
}


void JsonVisitor::visit(const LIEF::Symbol& symbol) {
  // It should be a ELF::Binary so we don't catch "std::bad_cast"
  this->visit(*dynamic_cast<const LIEF::PE::Symbol*>(&symbol));
}


void JsonVisitor::visit(const LIEF::Section& section) {
  // It should be a ELF::Binary so we don't catch "std::bad_cast"
  this->visit(*dynamic_cast<const LIEF::PE::Section*>(&section));
}

} // namespace PE
} // namespace LIEF

