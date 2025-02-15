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
#include "LIEF/PE/LoadConfigurations/EnclaveConfiguration.hpp"
#include "PE/pyPE.hpp"

#include <string>
#include <sstream>

#include "pyIterator.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>

namespace LIEF::PE::py {

template<>
void create<EnclaveConfiguration>(nb::module_& m) {
  using namespace LIEF::py;
  using id_array_t = EnclaveConfiguration::id_array_t;

  nb::class_<EnclaveConfiguration> conf(m, "EnclaveConfiguration",
    "This class represents the enclave configuration"_doc);

  init_ref_iterator<EnclaveConfiguration::it_imports>(conf, "it_imports");

  conf
    .def_prop_rw("size",
      nb::overload_cast<>(&EnclaveConfiguration::size, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::size),
      R"doc(
      The size of the ``IMAGE_ENCLAVE_CONFIG64/IMAGE_ENCLAVE_CONFIG32`` structure,
      in bytes.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("min_required_config_size",
      nb::overload_cast<>(&EnclaveConfiguration::min_required_config_size, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::min_required_config_size),
      R"doc(
      The minimum size of the ``IMAGE_ENCLAVE_CONFIG(32,64)`` structure that the
      image loader must be able to process in order for the enclave to be usable.

      This member allows an enclave to inform an earlier version of the image
      loader that the image loader can safely load the enclave and ignore
      optional members added to ``IMAGE_ENCLAVE_CONFIG(32,64)`` for later versions
      of the enclave. If the size of ``IMAGE_ENCLAVE_CONFIG(32,64)`` that the image
      loader can process is less than ``MinimumRequiredConfigSize``, the enclave
      cannot be run securely.

      If ``MinimumRequiredConfigSize`` is zero, the minimum size of the
      ``IMAGE_ENCLAVE_CONFIG(32,64)`` structure that the image loader must be able
      to process in order for the enclave to be usable is assumed to be the size
      of the structure through and including the ``MinimumRequiredConfigSize`` member.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("policy_flags",
      nb::overload_cast<>(&EnclaveConfiguration::policy_flags, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::policy_flags),
      "A flag that indicates whether the enclave permits debugging."_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_ro("is_debuggable",
      nb::overload_cast<>(&EnclaveConfiguration::is_debuggable, nb::const_),
      "Whether this enclave can be debugged"_doc
    )

    .def_prop_rw("import_list_rva",
      nb::overload_cast<>(&EnclaveConfiguration::import_list_rva, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::import_list_rva),
      R"doc(
      The RVA of the array of images that the enclave image may import, with
      identity information for each image.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("import_entry_size",
      nb::overload_cast<>(&EnclaveConfiguration::import_entry_size, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::import_entry_size),
      R"doc(
      The size of each image in the array of images that the :attr:`~.import_list_rva`
      member points to.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("nb_imports",
      nb::overload_cast<>(&EnclaveConfiguration::nb_imports, nb::const_),
      R"doc(
      The number of images in the array of images that the :attr:`~.import_list_rva`
      member points to.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("imports",
      nb::overload_cast<>(&EnclaveConfiguration::imports),
      "Iterator over the enclave's imports"_doc,
      nb::keep_alive<0, 1>(), nb::rv_policy::reference_internal
    )

    .def_prop_rw("family_id",
      nb::overload_cast<>(&EnclaveConfiguration::family_id, nb::const_),
      nb::overload_cast<const id_array_t&>(&EnclaveConfiguration::family_id),
      R"doc(
      The family identifier that the author of the enclave assigned to the
      enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("image_id",
      nb::overload_cast<>(&EnclaveConfiguration::image_id, nb::const_),
      nb::overload_cast<const id_array_t&>(&EnclaveConfiguration::image_id),
      R"doc(
      The image identifier that the author of the enclave assigned to the enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("image_version",
      nb::overload_cast<>(&EnclaveConfiguration::image_version, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::image_version),
      R"doc(
      The version number that the author of the enclave assigned to the enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("security_version",
      nb::overload_cast<>(&EnclaveConfiguration::security_version, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::security_version),
      R"doc(
      The security version number that the author of the enclave assigned to the
      enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("enclave_size",
      nb::overload_cast<>(&EnclaveConfiguration::enclave_size, nb::const_),
      nb::overload_cast<uint64_t>(&EnclaveConfiguration::enclave_size),
      R"doc(
      The expected virtual size of the private address range for the enclave,
      in bytes.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("nb_threads",
      nb::overload_cast<>(&EnclaveConfiguration::nb_threads, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::nb_threads),
      R"doc(
      The maximum number of threads that can be created within the enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("enclave_flags",
      nb::overload_cast<>(&EnclaveConfiguration::enclave_flags, nb::const_),
      nb::overload_cast<uint32_t>(&EnclaveConfiguration::enclave_flags),
      R"doc(
      A flag that indicates whether the image is suitable for use as the primary
      image in the enclave.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    LIEF_DEFAULT_STR(EnclaveConfiguration);

}
}
