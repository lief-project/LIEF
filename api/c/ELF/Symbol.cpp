/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "Symbol.hpp"

namespace LIEF {
namespace ELF {

void init_c_dynamic_symbols(Elf_Binary_t* c_binary, Binary* binary) {
  Binary::it_dynamic_symbols dyn_symb = binary->dynamic_symbols();

  c_binary->dynamic_symbols = static_cast<Elf_Symbol_t**>(
      malloc((dyn_symb.size() + 1) * sizeof(Elf_Symbol_t**)));

  for (size_t i = 0; i < dyn_symb.size(); ++i) {
    Symbol& b_sym = dyn_symb[i];
    c_binary->dynamic_symbols[i] = static_cast<Elf_Symbol_t*>(malloc(sizeof(Elf_Symbol_t)));
    c_binary->dynamic_symbols[i]->name        = b_sym.name().c_str();
    c_binary->dynamic_symbols[i]->type        = static_cast<uint32_t>(b_sym.type());
    c_binary->dynamic_symbols[i]->binding     = static_cast<uint32_t>(b_sym.binding());
    c_binary->dynamic_symbols[i]->other       = b_sym.other();
    c_binary->dynamic_symbols[i]->shndx       = b_sym.shndx();
    c_binary->dynamic_symbols[i]->value       = b_sym.value();
    c_binary->dynamic_symbols[i]->size        = b_sym.size();
    c_binary->dynamic_symbols[i]->information = b_sym.information();
    c_binary->dynamic_symbols[i]->is_exported = b_sym.is_exported();
    c_binary->dynamic_symbols[i]->is_imported = b_sym.is_imported();
  }
  c_binary->dynamic_symbols[dyn_symb.size()] = nullptr;

}


void init_c_symtab_symbols(Elf_Binary_t* c_binary, Binary* binary) {
  Binary::it_symtab_symbols static_symb = binary->symtab_symbols();

  c_binary->symtab_symbols = static_cast<Elf_Symbol_t**>(
      malloc((static_symb.size() + 1) * sizeof(Elf_Symbol_t**)));

  for (size_t i = 0; i < static_symb.size(); ++i) {
    Symbol& b_sym = static_symb[i];
    c_binary->symtab_symbols[i]              = static_cast<Elf_Symbol_t*>(malloc(sizeof(Elf_Symbol_t)));
    c_binary->symtab_symbols[i]->name        = b_sym.name().c_str();
    c_binary->symtab_symbols[i]->type        = static_cast<uint32_t>(b_sym.type());
    c_binary->symtab_symbols[i]->binding     = static_cast<uint32_t>(b_sym.binding());
    c_binary->symtab_symbols[i]->other       = b_sym.other();
    c_binary->symtab_symbols[i]->shndx       = b_sym.shndx();
    c_binary->symtab_symbols[i]->value       = b_sym.value();
    c_binary->symtab_symbols[i]->size        = b_sym.size();
    c_binary->symtab_symbols[i]->information = b_sym.information();
    c_binary->symtab_symbols[i]->is_exported = b_sym.is_exported();
    c_binary->symtab_symbols[i]->is_imported = b_sym.is_imported();
  }
  c_binary->symtab_symbols[static_symb.size()] = nullptr;

}



void destroy_dynamic_symbols(Elf_Binary_t* c_binary) {
  Elf_Symbol_t **dynamic_symbols = c_binary->dynamic_symbols;
  for (size_t idx = 0; dynamic_symbols[idx] != nullptr; ++idx) {
    free(dynamic_symbols[idx]);
  }
  free(c_binary->dynamic_symbols);
}


void destroy_symtab_symbols(Elf_Binary_t* c_binary) {
  Elf_Symbol_t **symtab_symbols = c_binary->symtab_symbols;
  for (size_t idx = 0; symtab_symbols[idx] != nullptr; ++idx) {
    free(symtab_symbols[idx]);
  }
  free(c_binary->symtab_symbols);
}

}
}


