/* Copyright 2022 - 2026 R. Thomas
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
#include <array>

#include "jni/lief/pe/LoadConfiguration.hpp"
#include "jni/lief/pe/CodeIntegrity.hpp"
#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::pe {

int LoadConfiguration::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "getSize",
      "()I",
      jni_get_size
    ),

    make(
      "getTimedatestamp",
      "()I",
      jni_get_timedatestamp
    ),

    make(
      "getMajorVersion",
      "()S",
      jni_get_major_version
    ),

    make(
      "getMinorVersion",
      "()S",
      jni_get_minor_version
    ),

    make(
      "getGlobalFlagsClear",
      "()I",
      jni_get_global_flags_clear
    ),

    make(
      "getGlobalFlagsSet",
      "()I",
      jni_get_global_flags_set
    ),

    make(
      "getCriticalSectionDefaultTimeout",
      "()I",
      jni_get_critical_section_default_timeout
    ),

    make(
      "getDeCommitFreeBlockThreshold",
      "()J",
      jni_get_decommit_free_block_threshold
    ),

    make(
      "getDeCommitTotalFreeThreshold",
      "()J",
      jni_get_decommit_total_free_threshold
    ),

    make(
      "getLockPrefixTable",
      "()J",
      jni_get_lock_prefix_table
    ),

    make(
      "getMaximumAllocationSize",
      "()J",
      jni_get_maximum_allocation_size
    ),

    make(
      "getVirtualMemoryThreshold",
      "()J",
      jni_get_virtual_memory_threshold
    ),

    make(
      "getProcessAffinityMask",
      "()J",
      jni_get_process_affinity_mask
    ),

    make(
      "getProcessHeapFlags",
      "()I",
      jni_get_process_heap_flags
    ),

    make(
      "getCsdVersion",
      "()S",
      jni_get_csd_version
    ),

    make(
      "getDependentLoadFlags",
      "()S",
      jni_get_dependent_load_flags
    ),

    make(
      "getEditList",
      "()J",
      jni_get_editlist
    ),

    make(
      "getSecurityCookie",
      "()J",
      jni_get_security_cookie
    ),

    make(
      "getSEHandlerTable",
      "()Ljava/util/OptionalLong;",
      jni_get_seh_table
    ),

    make(
      "getSEHandlerCount",
      "()Ljava/util/OptionalLong;",
      jni_get_seh_count
    ),

    make(
      "getGuardCfcCheckFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_cf_check_function_pointer
    ),

    make(
      "getGuardCfDispatchFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_cf_dispatch_function_pointer
    ),

    make(
      "getGuardCfFunctionTable",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_cf_function_table
    ),

    make(
      "getGuardCfFunctionCount",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_cf_function_count
    ),

    make(
      "getGuardFlags",
      "()Ljava/util/OptionalInt;",
      jni_get_guard_flags
    ),

    make(
      "getCodeIntegrity",
      "()Ljava/util/Optional;",
      jni_get_code_integrity
    ),

    make(
      "getGuardAddressTakenIatEntryTable",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_address_taken_iat_entry_table
    ),

    make(
      "getGuardAddressTakenIatEntryCount",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_address_taken_iat_entry_count
    ),

    make(
      "getGuardLongJumpTargetTable",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_long_jump_target_table
    ),

    make(
      "getGuardLongJumpTargetCount",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_long_jump_target_count
    ),

    make(
      "getDynamicValueRelocTable",
      "()Ljava/util/OptionalLong;",
      jni_get_dynamic_value_reloc_table
    ),

    make(
      "getCHPEMetadataPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_chpe_metadata_pointer
    ),

    make(
      "getCHPEMetadata",
      "()Ljava/util/Optional;",
      jni_get_chpe_metadata
    ),

    make(
      "getGuardRfFailureRoutine",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_rf_failure_routine
    ),

    make(
      "getGuardRfFailureRoutineFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_rf_failure_routine_function_pointer
    ),

    make(
      "getDynamicValueRelocTableOffset",
      "()Ljava/util/OptionalInt;",
      jni_get_dynamic_value_reloctable_offset
    ),

    make(
      "getDynamicValueRelocTableSection",
      "()Ljava/util/OptionalInt;",
      jni_get_dynamic_value_reloctable_section
    ),

    make(
      "getReserved2",
      "()Ljava/util/OptionalInt;",
      jni_get_reserved2
    ),

    make(
      "getGuardRfVerifyStackPointerFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_rf_verify_stack_pointer_function_pointer
    ),

    make(
      "getHotPatchTableOffset",
      "()Ljava/util/OptionalInt;",
      jni_get_hot_patch_table_offset
    ),

    make(
      "getReserved3",
      "()Ljava/util/OptionalInt;",
      jni_get_reserved3
    ),

    make(
      "getEnclaveConfigurationPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_enclave_configuration_pointer
    ),

    make(
      "getVolatileMetadataPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_volatile_metadata_pointer
    ),

    make(
      "getGuardEHContinuationTable",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_eh_continuation_table
    ),

    make(
      "getGuardEHContinuationCount",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_eh_continuation_count
    ),

    make(
      "getGuardXfgCheckFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_xfg_check_function_pointer
    ),

    make(
      "getGuardXfgDispatchFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_xfg_dispatch_function_pointer
    ),

    make(
      "getGuardXfgTableDispatchFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_xfg_table_dispatch_function_pointer
    ),

    make(
      "getCastGuardOsDeterminedFailureMode",
      "()Ljava/util/OptionalLong;",
      jni_get_cast_guard_os_determined_failure_mode
    ),

    make(
      "getGuardMemcpyFunctionPointer",
      "()Ljava/util/OptionalLong;",
      jni_get_guard_memcpy_function_pointer
    ),

    make(
      "getUmaFunctionPointers",
      "()Ljava/util/OptionalLong;",
      jni_get_uma_function_pointers
    ),

    make_destroy(
      &jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  CHPEMetadata::register_natives(env);
  CodeIntegrity::register_natives(env);

  return JNI_OK;
}

}
