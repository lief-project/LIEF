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
#include "PE/pyPE.hpp"

#include "LIEF/PE/LoadConfigurations.hpp"
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include "LIEF/PE/LoadConfigurations/DynamicRelocation/DynamicRelocationBase.hpp"
#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include "nanobind/extra/stl/lief_optional.h"

#include "pyIterator.hpp"

namespace LIEF::PE::py {

template<>
void create<LoadConfiguration>(nb::module_& m) {
  using namespace LIEF::py;

  create<CHPEMetadata>(m);
  create<DynamicRelocation>(m);
  create<EnclaveImport>(m);
  create<EnclaveConfiguration>(m);
  create<VolatileMetadata>(m);

  nb::class_<LoadConfiguration, LIEF::Object> config(m, "LoadConfiguration",
    R"delim(
    This class represents the load configuration data associated with the
    ``IMAGE_LOAD_CONFIG_DIRECTORY``.

    This structure is frequently updated by Microsoft to add new metadata.

    Reference: https://github.com/MicrosoftDocs/sdk-api/blob/cbeab4d371e8bc7e352c4d3a4c5819caa08c6a1c/sdk-api-src/content/winnt/ns-winnt-image_load_config_directory64.md#L2
    )delim"_doc);

  using guard_cf_function_t = LoadConfiguration::guard_function_t;
  nb::class_<guard_cf_function_t>(config, "guard_function_t")
    .def_rw("rva", &guard_cf_function_t::rva)
    .def_rw("extra", &guard_cf_function_t::extra);

  init_ref_iterator<LoadConfiguration::it_guard_functions>(config, "it_guard_functions");
  init_ref_iterator<LoadConfiguration::it_dynamic_relocations_t>(config, "it_dynamic_relocations_t");

  enum_<LoadConfiguration::IMAGE_GUARD>(config, "IMAGE_GUARD", nb::is_flag())
    #define ENTRY(X) .value(to_string(LoadConfiguration::IMAGE_GUARD::X), LoadConfiguration::IMAGE_GUARD::X)
      ENTRY(NONE)
      ENTRY(CF_INSTRUMENTED)
      ENTRY(CFW_INSTRUMENTED)
      ENTRY(CF_FUNCTION_TABLE_PRESENT)
      ENTRY(SECURITY_COOKIE_UNUSED)
      ENTRY(PROTECT_DELAYLOAD_IAT)
      ENTRY(DELAYLOAD_IAT_IN_ITS_OWN_SECTION)
      ENTRY(CF_EXPORT_SUPPRESSION_INFO_PRESENT)
      ENTRY(CF_ENABLE_EXPORT_SUPPRESSION)
      ENTRY(CF_LONGJUMP_TABLE_PRESENT)
      ENTRY(RF_INSTRUMENTED)
      ENTRY(RF_ENABLE)
      ENTRY(RF_STRICT)
      ENTRY(RETPOLINE_PRESENT)
      ENTRY(EH_CONTINUATION_TABLE_PRESENT)
    #undef ENTRY
  ;

  config
    .def_prop_rw("characteristics",
      nb::overload_cast<>(&LoadConfiguration::characteristics, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::characteristics),
      R"doc(
      Characteristics of the structure which is defined by its size
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("size",
      nb::overload_cast<>(&LoadConfiguration::size, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::size),
      "Size of the current structure"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("timedatestamp",
      nb::overload_cast<>(&LoadConfiguration::timedatestamp, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::timedatestamp),
      "The date and time stamp value"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("major_version",
      nb::overload_cast<>(&LoadConfiguration::major_version, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::major_version),
      "Major version"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("minor_version",
      nb::overload_cast<>(&LoadConfiguration::minor_version, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::minor_version),
      "Minor version"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("global_flags_clear",
      nb::overload_cast<>(&LoadConfiguration::global_flags_clear, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::global_flags_clear),
      R"doc(
      The global flags that control system behavior. For more information, see
      ``Gflags.exe``.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("global_flags_set",
      nb::overload_cast<>(&LoadConfiguration::global_flags_set, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::global_flags_set),
      R"doc(
      The global flags that control system behavior. For more information, see
      ``Gflags.exe``.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("critical_section_default_timeout",
      nb::overload_cast<>(&LoadConfiguration::critical_section_default_timeout, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::critical_section_default_timeout),
      "The critical section default time-out value."_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("decommit_free_block_threshold",
      nb::overload_cast<>(&LoadConfiguration::decommit_free_block_threshold, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::decommit_free_block_threshold),
      R"doc(
      The size of the minimum block that must be freed before it is freed
      (de-committed), in bytes. This value is advisory.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("decommit_total_free_threshold",
      nb::overload_cast<>(&LoadConfiguration::decommit_total_free_threshold, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::decommit_total_free_threshold),
      R"doc(
      The size of the minimum total memory that must be freed in the process
      heap before it is freed (de-committed), in bytes. This value is advisory.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("lock_prefix_table",
      nb::overload_cast<>(&LoadConfiguration::lock_prefix_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::lock_prefix_table),
      R"doc(
      The VA of a list of addresses where the ``LOCK`` prefix is used. These will
      be replaced by ``NOP`` on single-processor systems. This member is available
      only for ``x86``.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("maximum_allocation_size",
      nb::overload_cast<>(&LoadConfiguration::maximum_allocation_size, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::maximum_allocation_size),
      R"doc(
      The maximum allocation size, in bytes. This member is obsolete and is
      used only for debugging purposes.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("virtual_memory_threshold",
      nb::overload_cast<>(&LoadConfiguration::virtual_memory_threshold, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::virtual_memory_threshold),
      R"doc(
      The maximum block size that can be allocated from heap segments, in bytes.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("process_affinity_mask",
      nb::overload_cast<>(&LoadConfiguration::process_affinity_mask, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::process_affinity_mask),
      R"doc(
      The process affinity mask. For more information, see
      ``GetProcessAffinityMask``. This member is available only for ``.exe`` files.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("process_heap_flags",
      nb::overload_cast<>(&LoadConfiguration::process_heap_flags, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::process_heap_flags),
      "The process heap flags. For more information, see ``HeapCreate``."_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("csd_version",
      nb::overload_cast<>(&LoadConfiguration::csd_version, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::csd_version),
      "The service pack version."_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("dependent_load_flags",
      nb::overload_cast<>(&LoadConfiguration::dependent_load_flags, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::dependent_load_flags),
      R"doc(
      Alias for :attr:`~.reserved1`.

      The default load flags used when the operating system resolves the
      statically linked imports of a module. For more information, see
      ``LoadLibraryEx``.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("reserved1",
      nb::overload_cast<>(&LoadConfiguration::reserved1, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::dependent_load_flags),
      "See: :attr:`~.dependent_load_flags`"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("editlist",
      nb::overload_cast<>(&LoadConfiguration::editlist, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::editlist),
      "Reserved for use by the system."_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("security_cookie",
      nb::overload_cast<>(&LoadConfiguration::security_cookie, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::security_cookie),
      R"doc(
      A pointer to a cookie that is used by Visual C++ or GS implementation.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("se_handler_table",
      nb::overload_cast<>(&LoadConfiguration::se_handler_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::se_handler_table),
      R"doc(
      The VA of the sorted table of RVAs of each valid, unique handler in the
      image. This member is available only for x86.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("seh_functions",
      nb::overload_cast<>(&LoadConfiguration::seh_functions, nb::const_),
      "Return the list of the function RVA in the SEH table (if any)"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("se_handler_count",
      nb::overload_cast<>(&LoadConfiguration::se_handler_count, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::se_handler_count),
      R"doc(
      The count of unique handlers in the table. This member is available only
      for x86.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_cf_check_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_cf_check_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_cf_check_function_pointer),
      R"doc(
      The VA where Control Flow Guard check-function pointer is stored.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_cf_dispatch_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_cf_dispatch_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_cf_dispatch_function_pointer),
      R"doc(
      The VA where Control Flow Guard dispatch-function pointer is stored.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_cf_function_table",
      nb::overload_cast<>(&LoadConfiguration::guard_cf_function_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_cf_function_table),
      R"doc(
      The VA of the sorted table of RVAs of each Control Flow Guard function in
      the image.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_cf_function_count",
      nb::overload_cast<>(&LoadConfiguration::guard_cf_function_count, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_cf_function_count),
      R"doc(
      The count of unique RVAs in the :attr:`~.guard_cf_function_table` table.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("guard_cf_functions",
      nb::overload_cast<>(&LoadConfiguration::guard_cf_functions),
      R"doc(
      Iterator over the Control Flow Guard functions referenced by
      :attr:`~.guard_cf_function_table`
      )doc"_doc, nb::keep_alive<0, 1>(), nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_flags",
      nb::overload_cast<>(&LoadConfiguration::guard_flags, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::guard_flags),
      "Control Flow Guard related flags."_doc, nb::rv_policy::reference_internal
    )

    .def("has", nb::overload_cast<LoadConfiguration::IMAGE_GUARD>(&LoadConfiguration::has, nb::const_),
         "Check if the given flag is present"_doc)

    .def_prop_ro("guard_cf_flags_list",
      nb::overload_cast<>(&LoadConfiguration::guard_cf_flags_list, nb::const_),
      "List of flags"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("code_integrity",
      nb::overload_cast<>(&LoadConfiguration::code_integrity, nb::const_),
      nb::overload_cast<CodeIntegrity>(&LoadConfiguration::code_integrity),
      "Code integrity information."_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_address_taken_iat_entry_table",
      nb::overload_cast<>(&LoadConfiguration::guard_address_taken_iat_entry_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_address_taken_iat_entry_table),
      R"doc(
      The VA where Control Flow Guard address taken IAT table is stored.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_address_taken_iat_entry_count",
      nb::overload_cast<>(&LoadConfiguration::guard_address_taken_iat_entry_count, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_address_taken_iat_entry_count),
      R"doc(
      The count of unique RVAs in the table pointed by
      :attr:`~.guard_address_taken_iat_entry_table`.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("guard_address_taken_iat_entries",
      nb::overload_cast<>(&LoadConfiguration::guard_address_taken_iat_entries),
      R"doc(
      List of RVA pointed by :attr:`~.guard_address_taken_iat_entry_table`
      )doc"_doc
    )

    .def_prop_rw("guard_long_jump_target_table",
      nb::overload_cast<>(&LoadConfiguration::guard_long_jump_target_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_long_jump_target_table),
      R"doc(
      The VA where Control Flow Guard long jump target table is stored.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_long_jump_target_count",
      nb::overload_cast<>(&LoadConfiguration::guard_long_jump_target_count, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_long_jump_target_count),
      R"doc(
      The count of unique RVAs in the table pointed by
      :attr:`~.guard_long_jump_target_table`.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("guard_long_jump_targets",
      nb::overload_cast<>(&LoadConfiguration::guard_long_jump_targets),
      R"doc(
      List of RVA pointed by :attr:`~.guard_long_jump_target_table`
      )doc"_doc
    )

    .def_prop_rw("dynamic_value_reloc_table",
      nb::overload_cast<>(&LoadConfiguration::dynamic_value_reloc_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::dynamic_value_reloc_table),
      R"doc(
      VA pointing to a ``IMAGE_DYNAMIC_RELOCATION_TABLE``
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("hybrid_metadata_pointer",
      nb::overload_cast<>(&LoadConfiguration::hybrid_metadata_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::hybrid_metadata_pointer),
      R"doc(
      Alias for :attr:`~.chpe_metadata_pointer`.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("chpe_metadata_pointer",
      nb::overload_cast<>(&LoadConfiguration::chpe_metadata_pointer, nb::const_),
      R"doc(
      VA to the extra Compiled Hybrid Portable Executable (CHPE) metadata.
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_ro("chpe_metadata",
      nb::overload_cast<>(&LoadConfiguration::chpe_metadata),
      R"doc(
      Compiled Hybrid Portable Executable (CHPE) metadata (if any)
      )doc"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_rf_failure_routine",
      nb::overload_cast<>(&LoadConfiguration::guard_rf_failure_routine, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_rf_failure_routine),
      "VA of the failure routine"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_rf_failure_routine_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_rf_failure_routine_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_rf_failure_routine_function_pointer),
      "VA of the failure routine ``fptr``."_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("dynamic_value_reloctable_offset",
      nb::overload_cast<>(&LoadConfiguration::dynamic_value_reloctable_offset, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::dynamic_value_reloctable_offset),
      "Offset of dynamic relocation table relative to the relocation table"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("dynamic_value_reloctable_section",
      nb::overload_cast<>(&LoadConfiguration::dynamic_value_reloctable_section, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::dynamic_value_reloctable_section),
      "The section index of the dynamic value relocation table"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_ro("dynamic_relocations",
      nb::overload_cast<>(&LoadConfiguration::dynamic_relocations),
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>())

    .def_prop_rw("reserved2",
      nb::overload_cast<>(&LoadConfiguration::reserved2, nb::const_),
      nb::overload_cast<uint16_t>(&LoadConfiguration::reserved2),
      "Must be 0"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("guard_rf_verify_stackpointer_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_rf_verify_stackpointer_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_rf_verify_stackpointer_function_pointer),
      "VA of the Function verifying the stack pointer"_doc,
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("hotpatch_table_offset",
      nb::overload_cast<>(&LoadConfiguration::hotpatch_table_offset, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::hotpatch_table_offset),
      "Offset to the *hotpatch* table"_doc, nb::rv_policy::reference_internal
    )

    .def_prop_rw("reserved3",
      nb::overload_cast<>(&LoadConfiguration::reserved3, nb::const_),
      nb::overload_cast<uint32_t>(&LoadConfiguration::reserved3))

    .def_prop_rw("enclave_configuration_ptr",
      nb::overload_cast<>(&LoadConfiguration::enclave_configuration_ptr, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::enclave_configuration_ptr))

    .def_prop_ro("enclave_config",
      nb::overload_cast<>(&LoadConfiguration::enclave_config),
      nb::rv_policy::reference_internal
    )

    .def_prop_rw("volatile_metadata_pointer",
      nb::overload_cast<>(&LoadConfiguration::volatile_metadata_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::volatile_metadata_pointer))

    .def_prop_ro("volatile_metadata",
      nb::overload_cast<>(&LoadConfiguration::volatile_metadata))

    .def_prop_rw("guard_eh_continuation_table",
      nb::overload_cast<>(&LoadConfiguration::guard_eh_continuation_table, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_eh_continuation_table))

    .def_prop_rw("guard_eh_continuation_count",
      nb::overload_cast<>(&LoadConfiguration::guard_eh_continuation_count, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_eh_continuation_count))

    .def_prop_ro("guard_eh_continuation_functions",
      nb::overload_cast<>(&LoadConfiguration::guard_eh_continuation_functions),
      R"doc(
      List of RVA pointed by :attr:`~.guard_eh_continuation_table`
      )doc"_doc
    )

    .def_prop_rw("guard_xfg_check_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_xfg_check_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_xfg_check_function_pointer))

    .def_prop_rw("guard_xfg_dispatch_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_xfg_dispatch_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_xfg_dispatch_function_pointer))

    .def_prop_rw("guard_xfg_table_dispatch_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_xfg_table_dispatch_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_xfg_table_dispatch_function_pointer))

    .def_prop_rw("cast_guard_os_determined_failure_mode",
      nb::overload_cast<>(&LoadConfiguration::cast_guard_os_determined_failure_mode, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::cast_guard_os_determined_failure_mode))

    .def_prop_rw("guard_memcpy_function_pointer",
      nb::overload_cast<>(&LoadConfiguration::guard_memcpy_function_pointer, nb::const_),
      nb::overload_cast<uint64_t>(&LoadConfiguration::guard_memcpy_function_pointer))

  LIEF_COPYABLE(LoadConfiguration)
  LIEF_DEFAULT_STR(LoadConfiguration);
}
}
