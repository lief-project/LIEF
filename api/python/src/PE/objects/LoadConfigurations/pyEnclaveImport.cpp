/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/PE/LoadConfigurations/EnclaveImport.hpp"
#include "PE/pyPE.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

namespace LIEF::PE::py {

template<>
void create<EnclaveImport>(nb::module_& m) {
  using long_id_t = EnclaveImport::long_id_t;
  using short_id_t = EnclaveImport::short_id_t;

  nb::class_<EnclaveImport> imp(m, "EnclaveImport",
    "Defines an entry in the array of images that an enclave can import."_doc);

  using TYPE = EnclaveImport::TYPE;
  nb::enum_<TYPE>(imp, "TYPE")
    .value("NONE", TYPE::NONE,
      R"doc(
      None of the identifiers of the image need to match the value in the
      import record.
      )doc"_doc
    )

    .value("UNIQUE_ID", TYPE::UNIQUE_ID,
      R"doc(
      The value of the enclave unique identifier of the image must match the
      value in the import record. Otherwise, loading of the image fails.
      )doc"_doc
    )

    .value("AUTHOR_ID", TYPE::AUTHOR_ID,
      R"doc(
      The value of the enclave author identifier of the image must match the
      value in the import record. Otherwise, loading of the image fails. If
      this flag is set and the import record indicates an author identifier
      of all zeros, the imported image must be part of the Windows installation.
      )doc"_doc
    )

    .value("FAMILY_ID", TYPE::FAMILY_ID,
      R"doc(
 	    The value of the enclave family identifier of the image must match the
      value in the import record. Otherwise, loading of the image fails.
      )doc"_doc
    )

    .value("IMAGE_ID", TYPE::IMAGE_ID,
      R"doc(
      The value of the enclave image identifier of the image must match the
      value in the import record. Otherwise, loading of the image fail
      )doc"_doc
    )
  ;

  imp
    .def_prop_rw("type",
      nb::overload_cast<>(&EnclaveImport::type, nb::const_),
      nb::overload_cast<TYPE>(&EnclaveImport::type),
      R"doc(
      The type of identifier of the image that must match the value in the import
      record.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("min_security_version",
      nb::overload_cast<>(&EnclaveImport::min_security_version, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveImport::min_security_version),
      R"doc(
      The minimum enclave security version that each image must have for the
      image to be imported successfully. The image is rejected unless its enclave
      security version is equal to or greater than the minimum value in the
      import record. Set the value in the import record to zero to turn off the
      security version check.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("id",
      nb::overload_cast<>(&EnclaveImport::id, nb::const_),
      nb::overload_cast<const long_id_t&>(&EnclaveImport::id),
      R"doc(
      The unique identifier of the primary module for the enclave, if the
      :attr:`~.type` is :class:`~.TYPE.UNIQUE_ID`. Otherwise, the author
      identifier of the primary module for the enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("family_id",
      nb::overload_cast<>(&EnclaveImport::family_id, nb::const_),
      nb::overload_cast<const short_id_t&>(&EnclaveImport::family_id),
      "The family identifier of the primary module for the enclave."_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("image_id",
      nb::overload_cast<>(&EnclaveImport::image_id, nb::const_),
      nb::overload_cast<const short_id_t&>(&EnclaveImport::image_id),
      "The image identifier of the primary module for the enclave."_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("import_name_rva",
      nb::overload_cast<>(&EnclaveImport::import_name_rva, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveImport::import_name_rva),
      R"doc(
      The relative virtual address of a NULL-terminated string that contains the
      same value found in the import directory for the image.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("import_name",
      nb::overload_cast<>(&EnclaveImport::import_name, nb::const_),
      nb::overload_cast<std::string>(&EnclaveImport::import_name),
      "Resolved import name"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("reserved",
      nb::overload_cast<>(&EnclaveImport::reserved, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveImport::reserved),
      "Reserved. Should be 0"_doc, nb::rv_policy::reference_internal
    )

    LIEF_DEFAULT_STR(EnclaveImport);

}
}
