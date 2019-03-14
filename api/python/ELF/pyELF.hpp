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
#ifndef PY_LIEF_ELF_H_
#define PY_LIEF_ELF_H_

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"

#include "pyLIEF.hpp"


#define SPECIALIZE_CREATE(X)      \
  template<>                      \
  void create<X>(py::module&)

#define CREATE(X,Y) create<X>(Y)


namespace LIEF {
namespace ELF {

template<class T>
void create(py::module&);

void init_python_module(py::module& m);
void init_objects(py::module&);
void init_enums(py::module&);

void init_ELF32_sizes(py::module&);
void init_ELF64_sizes(py::module&);

SPECIALIZE_CREATE(Parser);
SPECIALIZE_CREATE(Binary);
SPECIALIZE_CREATE(Header);
SPECIALIZE_CREATE(Section);
SPECIALIZE_CREATE(Segment);
SPECIALIZE_CREATE(Symbol);
SPECIALIZE_CREATE(Relocation);
SPECIALIZE_CREATE(SymbolVersion);
SPECIALIZE_CREATE(SymbolVersionAux);
SPECIALIZE_CREATE(SymbolVersionRequirement);
SPECIALIZE_CREATE(SymbolVersionDefinition);
SPECIALIZE_CREATE(SymbolVersionAuxRequirement);
SPECIALIZE_CREATE(DynamicEntry);
SPECIALIZE_CREATE(DynamicEntryLibrary);
SPECIALIZE_CREATE(DynamicSharedObject);
SPECIALIZE_CREATE(DynamicEntryArray);
SPECIALIZE_CREATE(DynamicEntryRpath);
SPECIALIZE_CREATE(DynamicEntryRunPath);
SPECIALIZE_CREATE(DynamicEntryFlags);
SPECIALIZE_CREATE(GnuHash);
SPECIALIZE_CREATE(SysvHash);
SPECIALIZE_CREATE(Builder);
SPECIALIZE_CREATE(Note);
SPECIALIZE_CREATE(NoteDetails);
SPECIALIZE_CREATE(AndroidNote);
SPECIALIZE_CREATE(NoteAbi);
SPECIALIZE_CREATE(CorePrPsInfo);
SPECIALIZE_CREATE(CoreFile);
SPECIALIZE_CREATE(CoreFileEntry);



}
}


#endif
