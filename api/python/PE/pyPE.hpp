/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#ifndef PY_LIEF_PE_H_
#define PY_LIEF_PE_H_

#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>

#include <map>
#include <string>

#include "LIEF/PE.hpp"

#include "pyLIEF.hpp"

#define SPECIALIZE_CREATE(X)      \
  template<>                      \
  void create<X>(py::module&)

#define CREATE(X,Y) create<X>(Y)

namespace LIEF {
namespace PE {

template<class T>
void create(py::module&);

void init_python_module(py::module& m);
void init_objects(py::module&);
void init_enums(py::module&);
void init_utils(py::module&);

SPECIALIZE_CREATE(Parser);

SPECIALIZE_CREATE(Binary);
SPECIALIZE_CREATE(DosHeader);
SPECIALIZE_CREATE(Header);
SPECIALIZE_CREATE(OptionalHeader);
SPECIALIZE_CREATE(RichHeader);
SPECIALIZE_CREATE(RichEntry);
SPECIALIZE_CREATE(DataDirectory);
SPECIALIZE_CREATE(Section);
SPECIALIZE_CREATE(Relocation);
SPECIALIZE_CREATE(RelocationEntry);
SPECIALIZE_CREATE(Export);
SPECIALIZE_CREATE(ExportEntry);
SPECIALIZE_CREATE(TLS);
SPECIALIZE_CREATE(Symbol);
SPECIALIZE_CREATE(Debug);
SPECIALIZE_CREATE(CodeView);
SPECIALIZE_CREATE(CodeViewPDB);
SPECIALIZE_CREATE(Pogo);
SPECIALIZE_CREATE(PogoEntry);
SPECIALIZE_CREATE(Import);
SPECIALIZE_CREATE(ImportEntry);
SPECIALIZE_CREATE(DelayImport);
SPECIALIZE_CREATE(DelayImportEntry);
SPECIALIZE_CREATE(ResourceNode);
SPECIALIZE_CREATE(ResourceData);
SPECIALIZE_CREATE(ResourceDirectory);
SPECIALIZE_CREATE(ResourcesManager);
SPECIALIZE_CREATE(ResourceVersion);
SPECIALIZE_CREATE(ResourceStringFileInfo);
SPECIALIZE_CREATE(ResourceFixedFileInfo);
SPECIALIZE_CREATE(ResourceVarFileInfo);
SPECIALIZE_CREATE(LangCodeItem);
SPECIALIZE_CREATE(ResourceIcon);
SPECIALIZE_CREATE(ResourceStringTable);
SPECIALIZE_CREATE(ResourceDialog);
SPECIALIZE_CREATE(ResourceDialogItem);
SPECIALIZE_CREATE(ResourceAccelerator);

SPECIALIZE_CREATE(Signature);
SPECIALIZE_CREATE(RsaInfo);
SPECIALIZE_CREATE(x509);
SPECIALIZE_CREATE(SignerInfo);
SPECIALIZE_CREATE(Attribute);
SPECIALIZE_CREATE(ContentInfo);
SPECIALIZE_CREATE(ContentType);
SPECIALIZE_CREATE(GenericType);
SPECIALIZE_CREATE(MsSpcNestedSignature);
SPECIALIZE_CREATE(MsSpcStatementType);
SPECIALIZE_CREATE(PKCS9AtSequenceNumber);
SPECIALIZE_CREATE(PKCS9CounterSignature);
SPECIALIZE_CREATE(PKCS9MessageDigest);
SPECIALIZE_CREATE(PKCS9SigningTime);
SPECIALIZE_CREATE(SpcSpOpusInfo);

SPECIALIZE_CREATE(CodeIntegrity);
SPECIALIZE_CREATE(LoadConfiguration);
SPECIALIZE_CREATE(LoadConfigurationV0);
SPECIALIZE_CREATE(LoadConfigurationV1);
SPECIALIZE_CREATE(LoadConfigurationV2);
SPECIALIZE_CREATE(LoadConfigurationV3);
SPECIALIZE_CREATE(LoadConfigurationV4);
SPECIALIZE_CREATE(LoadConfigurationV5);
SPECIALIZE_CREATE(LoadConfigurationV6);
SPECIALIZE_CREATE(LoadConfigurationV7);

SPECIALIZE_CREATE(ResourcesManager);

SPECIALIZE_CREATE(Builder);

}
}


// Opaque containers
PYBIND11_MAKE_OPAQUE(std::vector<LIEF::PE::LangCodeItem>)
using dict_langcode_item = std::map<std::u16string, std::u16string>;
PYBIND11_MAKE_OPAQUE(dict_langcode_item)

#endif
